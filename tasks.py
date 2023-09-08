from invoke import task
from invoke.context import Context

from configuration import GALA_ROOT


@task
def autoformat(ctx: Context) -> None:
    path = GALA_ROOT
    print(f"\U000027A1 Running autoformat")
    ctx.run(
        f"autoflake -r --in-place --remove-all-unused-imports {path}",
        pty=True,
        echo=True,
    )
    ctx.run(f"isort {path}", pty=True, echo=True)
    ctx.run(f"black {path}", pty=True, echo=True)
    print("Finished running autoformat! \U0001F389")
