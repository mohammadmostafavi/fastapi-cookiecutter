import os
import shutil


licence = "{{cookiecutter.license}}"
project_slug = "{{cookiecutter.project_slug}}"
use_celery = "{{cookiecutter.use_celery}}"


def delete_resource(resource):
    if os.path.isfile(resource):
        print(f"removing file: {resource}")
        os.remove(resource)
    elif os.path.isdir(resource):
        print(f"removing directory: {resource}")
        shutil.rmtree(resource)


if licence == "None":
    delete_resource("LICENSE")

if use_celery == "n":
    delete_resource("{{cookiecutter.project_slug}}/src/celery.py")
    delete_resource("{{cookiecutter.project_slug}}/apps/user/tasks.py")
    delete_resource("{{cookiecutter.project_slug}}/apps/logs/tasks.py")