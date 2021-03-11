#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Release Parameters
BASE_VERSION=0.1.7
IS_RELEASE=false

SOURCE_REPO=agent-sdk
RELEASE_REPO=trustbloc/${SOURCE_REPO}
SNAPSHOT_REPO=trustbloc-cicd/snapshot
NPM_PKG_NAME=agent-sdk-web
DOCKER_PKG_NAME=agent-sdk-server

DOCKER_RELEASE_REPO=ghcr.io/trustbloc
DOCKER_SNAPSHOT_REPO=ghcr.io/trustbloc-cicd

if [ ${IS_RELEASE} = false ]
then
  EXTRA_VERSION=snapshot-$(git rev-parse --short=7 HEAD)
  PROJECT_VERSION=${BASE_VERSION}-${EXTRA_VERSION}
  PROJECT_PKG_REPO=${SNAPSHOT_REPO}
  NPM_PKG_NAME=trustbloc-cicd/${SOURCE_REPO}
  DOCKER_PROJECT_PKG_REPO=${DOCKER_SNAPSHOT_REPO}
else
  PROJECT_VERSION=${BASE_VERSION}
  PROJECT_PKG_REPO=${RELEASE_REPO}
  DOCKER_PROJECT_PKG_REPO=${DOCKER_RELEASE_REPO}
fi

export NPM_PKG_TAG=${PROJECT_VERSION}
export NPM_PKG_NAME=${NPM_PKG_NAME}
export NPM_PKG_REPO=${PROJECT_PKG_REPO}
export AGENT_SDK_TAG=${PROJECT_VERSION}
export AGENT_SDK_PKG=${DOCKER_PROJECT_PKG_REPO}/${DOCKER_PKG_NAME}
