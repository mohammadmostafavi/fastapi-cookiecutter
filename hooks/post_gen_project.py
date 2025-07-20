import os
import shutil


licence = "{{cookiecutter.license}}"
project_slug = "{{cookiecutter.project_slug}}"


def delete_resource(resource):
    if os.path.isfile(resource):
        print(f"removing file: {resource}")
        os.remove(resource)
    elif os.path.isdir(resource):
        print(f"removing directory: {resource}")
        shutil.rmtree(resource)


if licence == "None":
    delete_resource("LICENSE")
