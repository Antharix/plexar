"""
Plexar Digital Twin & Change Simulator.

Build a virtual model of your network from live state snapshots,
then safely simulate changes before pushing to production.

Usage:
    from plexar.twin import DigitalTwin

    twin = DigitalTwin()
    await twin.capture(network=net)

    result = twin.simulate_interface_failure("leaf-01", "Ethernet1")
    result = twin.simulate_bgp_peer_removal("spine-01", "10.0.0.2")
    result = twin.simulate_device_failure("spine-01")
    result = twin.validate_intent(intent)
"""

from plexar.twin.simulator import DigitalTwin, SimulationResult, IntentValidationResult

__all__ = ["DigitalTwin", "SimulationResult", "IntentValidationResult"]
