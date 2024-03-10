from hyperdx.opentelemetry import configure_opentelemetry


def post_fork(server, worker):
    configure_opentelemetry()
