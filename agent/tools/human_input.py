"""Pause and request human operator input."""

import sys
import logging

logger = logging.getLogger(__name__)


def run(question: str) -> str:
    print(f"\n{'=' * 55}")
    print(f"  Phantom requests human input:")
    print(f"  {question}")
    print(f"{'=' * 55}")

    try:
        if not sys.stdin.isatty():
            logger.warning("Human input requested in non-interactive mode")
            return "Human input requested but stdin is not a terminal (non-interactive mode)."
        answer = input("  Your answer: ").strip()
        print()
        logger.info("Human responded to: %s", question[:80])
        return f"Human response: {answer}" if answer else "Human provided no response."
    except (EOFError, KeyboardInterrupt):
        return "Human input unavailable."


TOOL_SPEC = {
    "name": "request_human_input",
    "description": (
        "Pause and ask the operator a question requiring human judgment "
        "(scope clarification, attack confirmation, credential input, etc.)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "The specific question to ask the operator",
            }
        },
        "required": ["question"],
    },
}
