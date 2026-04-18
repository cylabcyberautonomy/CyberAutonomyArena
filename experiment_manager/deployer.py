from .environment import DeployedEnvironment
from .experiment import Experiment


async def deploy_environment(experiment: Experiment) -> DeployedEnvironment:
    """Set up the OpenStack environment. Returns connection info."""
    # TODO: deploy experiment.environment_spec into a dedicated OpenStack project
    raise NotImplementedError("Environment deployment not yet implemented")
