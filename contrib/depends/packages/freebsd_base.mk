package=freebsd_base
$(package)_version=14.4
$(package)_download_path=https://download.freebsd.org/releases/amd64/$($(package)_version)-RELEASE/
$(package)_download_file=base.txz
$(package)_file_name=freebsd-base-$($(package)_version).txz
$(package)_sha256_hash=769f60a6eea2938ad6b7943cfbcc17dfaf7d1f7ba59a32b869a00349302df853

define $(package)_extract_cmds
  echo $($(package)_sha256_hash) $($(1)_source_dir)/$($(package)_file_name) | sha256sum -c &&\
  tar xf $($(1)_source_dir)/$($(package)_file_name) ./lib/ ./usr/lib/ ./usr/include/
endef

define $(package)_build_cmds
  mkdir bin &&\
  echo "#!/bin/sh\n\nexec /usr/bin/clang-14 -target x86_64-unknown-freebsd$($(package)_version) --sysroot=$(host_prefix)/native $$$$""@" > bin/clang-14 &&\
  echo "#!/bin/sh\n\nexec /usr/bin/clang++-14 -target x86_64-unknown-freebsd$($(package)_version) --sysroot=$(host_prefix)/native -stdlib=libc++ $$$$""@" > bin/clang++-14 &&\
  chmod 755 bin/*
endef

define $(package)_stage_cmds
  mkdir $($(package)_staging_dir)/$(host_prefix)/native &&\
  mv bin lib usr $($(package)_staging_dir)/$(host_prefix)/native
endef
