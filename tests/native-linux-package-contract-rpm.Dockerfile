FROM fedora@sha256:99e203b80b1c3d8f7e161ec10a68fd02b081ef83a3963553e513c82846b97814

RUN dnf --setopt=install_weak_deps=False --setopt=retries=3 --setopt=timeout=20 \
      --setopt=max_parallel_downloads=4 -y install ca-certificates rpm-build shadow-utils systemd \
 && dnf clean all \
 && rm -rf /var/cache/dnf
