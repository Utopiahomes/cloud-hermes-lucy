from lucy.api import app


def test_adapter_surface_has_no_approval_or_apply_route() -> None:
    exposed = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/v1/")
    }
    assert exposed == {
        ("GET", "/v1/memory/lookup"),
        ("POST", "/v1/memory/proposals"),
    }


def test_internal_surface_only_exposes_model_budget_bridge() -> None:
    exposed = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/internal/")
    }
    assert exposed == {
        ("POST", "/internal/v1/model-executions/begin"),
        ("POST", "/internal/v1/model-executions/settle"),
    }
