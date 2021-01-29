/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/extnetworkpolicy/v1alpha1"
	scheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/extnetworkpolicy/v1alpha1/apis/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ExtNetworkPoliciesGetter has a method to return a ExtNetworkPolicyInterface.
// A group's client should implement this interface.
type ExtNetworkPoliciesGetter interface {
	ExtNetworkPolicies(namespace string) ExtNetworkPolicyInterface
}

// ExtNetworkPolicyInterface has methods to work with ExtNetworkPolicy resources.
type ExtNetworkPolicyInterface interface {
	Create(ctx context.Context, extNetworkPolicy *v1alpha1.ExtNetworkPolicy, opts v1.CreateOptions) (*v1alpha1.ExtNetworkPolicy, error)
	Update(ctx context.Context, extNetworkPolicy *v1alpha1.ExtNetworkPolicy, opts v1.UpdateOptions) (*v1alpha1.ExtNetworkPolicy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ExtNetworkPolicy, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ExtNetworkPolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ExtNetworkPolicy, err error)
	ExtNetworkPolicyExpansion
}

// extNetworkPolicies implements ExtNetworkPolicyInterface
type extNetworkPolicies struct {
	client rest.Interface
	ns     string
}

// newExtNetworkPolicies returns a ExtNetworkPolicies
func newExtNetworkPolicies(c *K8sV1alpha1Client, namespace string) *extNetworkPolicies {
	return &extNetworkPolicies{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the extNetworkPolicy, and returns the corresponding extNetworkPolicy object, and an error if there is any.
func (c *extNetworkPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ExtNetworkPolicy, err error) {
	result = &v1alpha1.ExtNetworkPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ExtNetworkPolicies that match those selectors.
func (c *extNetworkPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ExtNetworkPolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ExtNetworkPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested extNetworkPolicies.
func (c *extNetworkPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a extNetworkPolicy and creates it.  Returns the server's representation of the extNetworkPolicy, and an error, if there is any.
func (c *extNetworkPolicies) Create(ctx context.Context, extNetworkPolicy *v1alpha1.ExtNetworkPolicy, opts v1.CreateOptions) (result *v1alpha1.ExtNetworkPolicy, err error) {
	result = &v1alpha1.ExtNetworkPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(extNetworkPolicy).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a extNetworkPolicy and updates it. Returns the server's representation of the extNetworkPolicy, and an error, if there is any.
func (c *extNetworkPolicies) Update(ctx context.Context, extNetworkPolicy *v1alpha1.ExtNetworkPolicy, opts v1.UpdateOptions) (result *v1alpha1.ExtNetworkPolicy, err error) {
	result = &v1alpha1.ExtNetworkPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		Name(extNetworkPolicy.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(extNetworkPolicy).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the extNetworkPolicy and deletes it. Returns an error if one occurs.
func (c *extNetworkPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *extNetworkPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched extNetworkPolicy.
func (c *extNetworkPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ExtNetworkPolicy, err error) {
	result = &v1alpha1.ExtNetworkPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("extnetworkpolicies").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
