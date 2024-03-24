FROM debian:sid-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    python3-gitlab \
    python3-yaml \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV HOME /home/user
RUN adduser --disabled-password user --home $HOME --gecos ""
USER user

COPY ./gitlab-rulez /usr/local/bin

ENTRYPOINT ["gitlab-rulez"]

LABEL org.label-schema.name "gitlab-rulez"
LABEL org.label-schema.description "Configure settings on GitLab based on YAML rules"
LABEL org.label-schema.docker.cmd "docker run --rm \
   -w $(pwd) -v $(pwd):$(pwd) \
   --mount type=bind,source=$HOME/.python-gitlab.cfg,target=/home/user/.python-gitlab.cfg \
   --security-opt label=disable"
