import asyncio
import json
import os
import sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text())
out = Path(cfg["output_dir"])
out.mkdir(parents=True, exist_ok=True)

os.environ["CAI_MODEL"] = cfg["model"]
if cfg.get("api_base"):
    os.environ["OPENAI_API_BASE"] = cfg["api_base"]
    os.environ["OPENAI_BASE_URL"] = cfg["api_base"]
if cfg.get("api_key"):
    _anthropic = "claude" in cfg["model"] or "anthropic" in cfg["model"]
    os.environ["ANTHROPIC_API_KEY" if _anthropic else "OPENAI_API_KEY"] = cfg["api_key"]

from cai.sdk.agents import Runner, RunConfig, function_tool, set_tracing_disabled

set_tracing_disabled(True)

from cai.agents.red_teamer import redteam_agent


@function_tool
def finish(summary: str) -> str:
    """Call this when the objective is complete or no further progress is possible, then stop.

    Args:
        summary: a brief summary of what was accomplished.
    """
    return "Acknowledged. Provide your final summary and stop."


redteam_agent.tools.append(finish)
redteam_agent.input_guardrails = []
redteam_agent.output_guardrails = []


async def main() -> int:
    result = await Runner.run(redteam_agent, input=cfg["objective"], max_turns=sys.maxsize,
                              run_config=RunConfig(tracing_disabled=True))
    tin = sum(r.usage.input_tokens for r in result.raw_responses)
    tout = sum(r.usage.output_tokens for r in result.raw_responses)
    (out / "token_usage.json").write_text(json.dumps({
        "input_tokens": tin, "output_tokens": tout, "total_tokens": tin + tout,
        "requests": sum(r.usage.requests for r in result.raw_responses)}))
    (out / "transcript.json").write_text(json.dumps(result.to_input_list(), default=str, indent=2))
    (out / "final_output.txt").write_text(str(result.final_output))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
