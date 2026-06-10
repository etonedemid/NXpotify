FROM devkitpro/devkitppc:latest

RUN dkp-pacman -Syu --noconfirm \
        wut \
        wiiu-sdl2 \
        wiiu-sdl2_ttf \
        wiiu-curl \
        wiiu-mbedtls \
        wiiu-libvorbisidec \
    && dkp-pacman -Sc --noconfirm
