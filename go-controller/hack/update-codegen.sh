#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

crds=$(ls pkg/crd 2> /dev/null)
if [ -z "${crds}" ]; then
  exit
fi

if  ! ( command -v controller-gen > /dev/null ); then
  echo "controller-gen not found, installing sigs.k8s.io/controller-tools"
  olddir="${PWD}"
  builddir="$(mktemp -d)"
  cd "${builddir}"
  GO111MODULE=on go get -u sigs.k8s.io/controller-tools/cmd/controller-gen
  cd "${olddir}"
  if [[ "${builddir}" == /tmp/* ]]; then #paranoia
      rm -rf "${builddir}"
  fi
fi

for crd in ${crds}; do
  vers=$(ls pkg/crd/$crd 2> /dev/null)
  echo "Generating deepcopy funcs for $crd:$vers"
  deepcopy-gen \
    --input-dirs github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/${vers} \
    -O zz_generated.deepcopy \
    --bounding-dirs github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd


  echo "Generating clientset for $crd"
  client-gen \
    --clientset-name "${CLIENTSET_NAME_VERSIONED:-versioned}" \
    --input-base "" \
    --input github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers \
    --output-package github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers/apis/clientset \
    "$@"

  echo "Generating listers for $crd"
  lister-gen \
    --input-dirs github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers \
    --output-package github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers/apis/listers \
    "$@"

  echo "Generating informers for $crd"
  informer-gen \
    --input-dirs github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers \
    --versioned-clientset-package github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers/apis/clientset/versioned \
    --listers-package  github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers/apis/listers \
    --output-package github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/$crd/$vers/apis/informers \
    "$@"
done

echo "Generating CRDs"
mkdir -p _output/crds
controller-gen crd:crdVersions="v1"  paths=./pkg/crd/... output:crd:dir=_output/crds
echo "Editing egressFirewall CRD"
## We desire that only egressFirewalls with the name "default" are accepted by the apiserver. The only
## way that we can put a pattern for validation on the name of the object which is embedded in
## metav1.ObjectMeta it is required that we add it after the generation of the CRD.
sed -i -e':begin;$!N;s/.*metadata:\n.*type: object/&\n            properties:\n              name:\n                type: string\n                pattern: ^default$/;P;D' \
	_output/crds/k8s.ovn.org_egressfirewalls.yaml
## It is also required that we restrict the number of properties on the 'to' section of the egressfirewall
## so that either 'dnsName' or 'cidrSelector is set in the crd and currently kubebuilder does not support
## adding validation to objects only to the fields
sed -i -e ':begin;$!N;s/                          type: string\n.*type: object/&\n                      minProperties: 1\n                      maxProperties: 1/;P;D' \
	_output/crds/k8s.ovn.org_egressfirewalls.yaml
