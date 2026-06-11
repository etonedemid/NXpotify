FROM devkitpro/devkitppc:latest

RUN dkp-pacman -Syu --noconfirm wiiu-dev \
    && dkp-pacman -Sc --noconfirm

# Native Rust toolchain + tools needed for setup-tool / bundle Linux builds
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl musl-tools libasound2-dev pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
       | sh -s -- -y --default-toolchain stable --profile minimal \
       --target x86_64-unknown-linux-musl \
    && rm -rf /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/share/doc

ENV PATH="/root/.cargo/bin:${PATH}"
