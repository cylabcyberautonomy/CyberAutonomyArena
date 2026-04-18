from .models import Experiment


async def teardown_environment(experiment: Experiment) -> None:
    """Tear down the OpenStack environment."""
    # TODO: delete OpenStack project for experiment.deployed_environment.openstack_id
    raise NotImplementedError("Environment teardown not yet implemented")
