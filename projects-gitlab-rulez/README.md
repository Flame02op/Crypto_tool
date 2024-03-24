> ✍️ Note!
>
> Beginning with Apertis pro release v2023 only the branch specific GitLab project
> configuration is supported, see [ci-package-builder](https://gitlab-apertispro.boschdevcloud.com/demo/infrastructure/ci-package-builder/-/tree/apertispro/v2023?ref_type=heads).
> The environment variables OBS_PROJECT and RELEASE_VERSION have to be defined
> within the file `debian/apertispro/.gitlab-ci.yml`.

gitlab-rulez
============

Compute and apply changes to the settings of the projects in a GitLab instance
based on a set of YAML rules.

First, configure the GitLab access credentials for python-gitlab
as given below on your Apertispro SDK. Replace the private_token.

1 A sample configuration file in /home/user/.python-gitlab.cfg looks like

    [global]
    default = apertispro-gitlab
    ssl_verify = true
    timeout = 5

    [apertispro-gitlab]
    url = https://gitlab-apertispro.boschdevcloud.com/
    private_token = YOUR_PRIVTE_TOKEN
    api_version = 4

2 Clone the project on your SDK and change the directory to projects-gitlab-rulez

    $ git clone -b apertispro/v2023 https://gitlab-apertispro.boschdevcloud.com/demo/infrastructure/projects-gitlab-rulez.git
    $ cd projects-gitlab-rulez

3 Update the rulez-custom.yaml file with **your project specific values**.
Then check what currently violates the rules so far defined:

    ./gitlab-rulez diff ./rulez-custom.yaml --filter demo/main/demo-hello

4 If what gitlab-rulez highlights seem sensible, tell it to poke your GitLab
instance until it is happy:

    ./gitlab-rulez apply ./rulez-custom.yaml --filter demo/main/demo-hello

**Note: Due to know issues, we need to apply rulez multiple times till ```computed 0 actions```
appers in commandline.**

