"""Agentic loop with parallel tool execution and state persistence."""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools import ALL_TOOLS, get_tool_mapping
from providers import get_provider

logger = logging.getLogger(__name__)


class AgentClient:

    def __init__(self, config: dict):
        self.provider = get_provider(config)
        self.raw_tools = ALL_TOOLS
        self.tools = self.provider.convert_tools(ALL_TOOLS)
        self.mapping = get_tool_mapping()
        self.max_parallel = config.get("max_parallel_tools", 4)
        self.compact_after = config.get("context_compact_after", 5)

    def _compact_old_tool_results(self, messages: list, keep_last_n: int = 3) -> list:
        """Truncate content of old tool_result blocks to avoid context overflow."""
        tool_result_indices = [
            i for i, m in enumerate(messages)
            if m.get("role") == "user"
            and isinstance(m.get("content"), list)
            and any(b.get("type") == "tool_result" for b in m["content"])
        ]
        to_compact = set(tool_result_indices[:-keep_last_n]) if len(tool_result_indices) > keep_last_n else set()
        if not to_compact:
            return messages

        result = []
        for i, msg in enumerate(messages):
            if i in to_compact:
                compacted = []
                for block in msg["content"]:
                    if block.get("type") == "tool_result":
                        content = str(block.get("content", ""))
                        if len(content) > 400:
                            block = {**block, "content": content[:400] + " [...compacted]"}
                    compacted.append(block)
                result.append({**msg, "content": compacted})
            else:
                result.append(msg)
        return result

    def _execute_tool(self, tc: dict) -> dict:
        """Execute a single tool call and return the result block."""
        tool_func = self.mapping.get(tc["name"])
        if not tool_func:
            logger.warning("Unknown tool: %s", tc["name"])
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": f"Unknown tool: {tc['name']}",
            }

        try:
            result = tool_func(**tc["input"])
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": str(result),
            }
        except Exception as e:
            error_msg = f"Error {tc['name']}: {str(e)}"
            logger.error(error_msg)
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": error_msg,
            }

    def _execute_tools_parallel(self, tool_calls: list) -> list:
        """Execute multiple tool calls in parallel."""
        if len(tool_calls) == 1:
            return [self._execute_tool(tool_calls[0])]

        results = [None] * len(tool_calls)
        with ThreadPoolExecutor(max_workers=min(len(tool_calls), self.max_parallel)) as executor:
            future_to_idx = {
                executor.submit(self._execute_tool, tc): i
                for i, tc in enumerate(tool_calls)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        "type": "tool_result",
                        "tool_use_id": tool_calls[idx]["id"],
                        "content": f"Execution error: {str(e)}",
                    }
        return results

    def think(self, messages: list, system_prompt: str) -> list:
        messages = self._compact_old_tool_results(messages)
        text_blocks, tool_calls = self.provider.call(messages, system_prompt, self.tools)

        new_messages = messages.copy()

        # Build assistant message
        assistant_blocks = []
        for text in text_blocks:
            print("Phantom:", text)
            logger.info("Reasoning: %s", text[:300])
            assistant_blocks.append({"type": "text", "text": text})

        for tc in tool_calls:
            assistant_blocks.append({
                "type": "tool_use",
                "id": tc["id"],
                "name": tc["name"],
                "input": tc["input"],
            })

        if assistant_blocks:
            new_messages.append({"role": "assistant", "content": assistant_blocks})

        # Execute tools (parallel if multiple)
        if tool_calls:
            logger.info("Executing %d tool(s): %s",
                       len(tool_calls), [tc["name"] for tc in tool_calls])
            tool_results = self._execute_tools_parallel(tool_calls)

            if tool_results:
                new_messages.append({"role": "user", "content": tool_results})

        return new_messages

    def save_state(self, messages: list, turn: int, session_dir: str):
        """Persist mission state for resume capability."""
        import os
        state = {
            "turn": turn,
            "messages": messages,
        }
        state_path = os.path.join(session_dir, "state.json")
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=1)
        logger.debug("State saved at turn %d", turn)

    @staticmethod
    def load_state(session_dir: str) -> dict | None:
        """Load mission state from a session directory."""
        import os
        state_path = os.path.join(session_dir, "state.json")
        if not os.path.exists(state_path):
            return None
        with open(state_path, encoding="utf-8") as f:
            return json.load(f)
