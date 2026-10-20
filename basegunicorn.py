def post_fork(server, worker):
    """Executes in each worker process right after it is forked."""
    import django
    import os
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authome.settings")
    django.setup()

    from authome import models
    models.initialize()
