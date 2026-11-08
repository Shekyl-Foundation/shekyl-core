# Copyright (c) 2025-2026, The Shekyl Foundation
# Copyright (c) 2014-2022, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

dotgit=$(shell ls -d .git/config)
ifneq ($(dotgit), .git/config)
  USE_SINGLE_BUILDDIR=1
endif

subbuilddir:=$(shell echo  `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch | grep '\* ' | cut -f2- -d' '| sed -e 's|[:/\\ \(\)]|_|g'`)
ifeq ($(USE_SINGLE_BUILDDIR),)
  builddir := build/"$(subbuilddir)"
  topdir   := ../../../..
  deldirs  := $(builddir)
else
  builddir := build
  topdir   := ../..
  deldirs  := $(builddir)/debug $(builddir)/release
endif

all: release-all

depends:
	cd contrib/depends && $(MAKE) HOST=$(target) && cd ../.. && mkdir -p build/$(target)/release
	cd build/$(target)/release && cmake -DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/contrib/depends/$(target)/share/toolchain.cmake ../../.. && $(MAKE)

cmake-debug:
	mkdir -p $(builddir)/debug
	cd $(builddir)/debug && cmake -D CMAKE_BUILD_TYPE=Debug $(topdir)

debug: cmake-debug
	cd $(builddir)/debug && $(MAKE)

debug-all:
	mkdir -p $(builddir)/debug
	cd $(builddir)/debug && cmake -D CMAKE_BUILD_TYPE=Debug $(topdir) && $(MAKE)

debug-static-all:
	mkdir -p $(builddir)/debug
	cd $(builddir)/debug && cmake -D STATIC=ON -D CMAKE_BUILD_TYPE=Debug $(topdir) && $(MAKE)

debug-static-win64:
	mkdir -p $(builddir)/debug
	cd $(builddir)/debug && cmake -G "MSYS Makefiles" -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Debug -D BUILD_TAG="win-x64" -D CMAKE_TOOLCHAIN_FILE=$(topdir)/cmake/mingw-toolchain.cmake -D MSYS2_FOLDER=$(shell cd ${MINGW_PREFIX}/.. && pwd -W) $(topdir) && $(MAKE)
 
cmake-release:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D CMAKE_BUILD_TYPE=Release $(topdir)

release: cmake-release
	cd $(builddir)/release && $(MAKE)

release-all:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE)

release-seed:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D CMAKE_BUILD_TYPE=Release -D ARCH="x86-64" $(topdir) && $(MAKE)

release-static:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D STATIC=ON -D CMAKE_BUILD_TYPE=Release $(topdir) && $(MAKE)

# Targets for specific prebuilt builds which will be advertised for updates by their build tag

release-static-linux-armv8:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D ARCH="armv8-a" -D STATIC=ON -D CMAKE_BUILD_TYPE=Release -D BUILD_TAG="linux-armv8" $(topdir) && $(MAKE)

release-static-linux-x86_64:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release -D BUILD_TAG="linux-x64" $(topdir) && $(MAKE)

release-static-freebsd-x86_64:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release -D BUILD_TAG="freebsd-x64" $(topdir) && $(MAKE)

release-static-mac-x86_64:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release -D BUILD_TAG="mac-x64" $(topdir) && $(MAKE)

release-static-win64:
	mkdir -p $(builddir)/release
	cd $(builddir)/release && cmake -G "MSYS Makefiles" -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release -D BUILD_TAG="win-x64" -D CMAKE_TOOLCHAIN_FILE=$(topdir)/cmake/mingw-toolchain.cmake -D MSYS2_FOLDER=$(shell cd ${MINGW_PREFIX}/.. && pwd -W) $(topdir) && $(MAKE)

clean:
	@echo "WARNING: Back-up your wallet if it exists within ./"$(deldirs)"!" ; \
    read -r -p "This will destroy the build directory, continue (y/N)?: " CONTINUE; \
	[ $$CONTINUE = "y" ] || [ $$CONTINUE = "Y" ] || (echo "Exiting."; exit 1;)
	rm -rf $(deldirs)

clean-all:
	@echo "WARNING: Back-up your wallet if it exists within ./build!" ; \
	read -r -p "This will destroy all build directories, continue (y/N)?: " CONTINUE; \
	[ $$CONTINUE = "y" ] || [ $$CONTINUE = "Y" ] || (echo "Exiting."; exit 1;)
	rm -rf ./build

.PHONY: all cmake-debug debug debug-all cmake-release release release-all release-seed clean
