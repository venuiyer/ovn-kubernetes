package v1alpha1

import (
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// This is taken from the networking API spec del since we want the
// format for the Extended Network Policies to follow the K8s Network
// Policies and also so that we can resuse the existing ovn-k8s code
// that implements K8s Network Policies. The only place it deviates
// is in NetworkPolicyPort below, where we use "type" insted of "port",
// as we intend to use this for ICMP to begin with, and Protocol as a
// string so that we can validate.
// This means we need to closely monitor K8s API changes

// PolicyType describes the NetworkPolicy type
// type PolicyType string

const (
	// PolicyTypeIngress is a NetworkPolicy that affects ingress traffic on selected pods
	PolicyTypeIngress knet.PolicyType = "Ingress"
	// PolicyTypeEgress is a NetworkPolicy that affects egress traffic on selected pods
	PolicyTypeEgress knet.PolicyType = "Egress"
)

// ExtNetworkPolicySpec provides the specification of a NetworkPolicy
type ExtNetworkPolicySpec struct {
	// Selects the pods to which this NetworkPolicy object applies. The array of
	// ingress rules is applied to any pods selected by this field. Multiple network
	// policies can select the same set of pods. In this case, the ingress rules for
	// each are combined additively. This field is NOT optional and follows standard
	// label selector semantics. An empty podSelector matches all pods in this
	// namespace.
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// List of ingress rules to be applied to the selected pods. Traffic is allowed to
	// a pod if there are no NetworkPolicies selecting the pod
	// (and cluster policy otherwise allows the traffic), OR if the traffic source is
	// the pod's local node, OR if the traffic matches at least one ingress rule
	// across all of the NetworkPolicy objects whose podSelector matches the pod. If
	// this field is empty then this NetworkPolicy does not allow any traffic (and serves
	// solely to ensure that the pods it selects are isolated by default)
	// +optional
	Ingress []NetworkPolicyIngressRule `json:"ingress,omitempty"`

	// List of egress rules to be applied to the selected pods. Outgoing traffic is
	// allowed if there are no NetworkPolicies selecting the pod (and cluster policy
	// otherwise allows the traffic), OR if the traffic matches at least one egress rule
	// across all of the NetworkPolicy objects whose podSelector matches the pod. If
	// this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
	// solely to ensure that the pods it selects are isolated by default).
	// +optional
	Egress []NetworkPolicyEgressRule `json:"egress,omitempty"`

	// List of rule types that the NetworkPolicy relates to.
	// Valid options are "Ingress", "Egress", or "Ingress,Egress".
	// If this field is not specified, it will default based on the existence of Ingress or Egress rules;
	// policies that contain an Egress section are assumed to affect Egress, and all policies
	// (whether or not they contain an Ingress section) are assumed to affect Ingress.
	// If you want to write an egress-only policy, you must explicitly specify policyTypes [ "Egress" ].
	// Likewise, if you want to write a policy that specifies that no egress is allowed,
	// you must specify a policyTypes value that include "Egress" (since such a policy would not include
	// an Egress section and would otherwise default to just [ "Ingress" ]).
	// +optional
	PolicyTypes []knet.PolicyType `json:"policyTypes,omitempty"`
}

// NetworkPolicyIngressRule describes a particular set of traffic that is allowed to the pods
// matched by a ExtNetworkPolicySpec's podSelector. The traffic must match both ports and from.
type NetworkPolicyIngressRule struct {
	// List of ports which should be made accessible on the pods selected for this
	// rule. Each item in this list is combined using a logical OR. If this field is
	// empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`

	// List of sources which should be able to access the pods selected for this rule.
	// Items in this list are combined using a logical OR operation. If this field is
	// empty or missing, this rule matches all sources (traffic not restricted by
	// source). If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the from list.
	// +optional
	From []NetworkPolicyPeer `json:"from,omitempty"`
}

// NetworkPolicyEgressRule describes a particular set of traffic that is allowed out of pods
// matched by a ExtNetworkPolicySpec's podSelector. The traffic must match both ports and to.
type NetworkPolicyEgressRule struct {
	// List of destination ports for outgoing traffic.
	// Each item in this list is combined using a logical OR. If this field is
	// empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`

	// List of destinations for outgoing traffic of pods selected for this rule.
	// Items in this list are combined using a logical OR operation. If this field is
	// empty or missing, this rule matches all destinations (traffic not restricted by
	// destination). If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the to list.
	// +optional
	To []NetworkPolicyPeer `json:"to,omitempty"`
}

// NetworkPolicyPort describes a port to allow traffic on
// TODO: Add ICMP code, if needed.
type NetworkPolicyPort struct {
	// The protocol which traffic must match. Non-ICMP are configured
	// via K8s network policy, so this must be ICMP.
	// We use a string to enforce ICMP as the acceptable value
	// +kubebuilder:validation:Pattern=^ICMP$
	Protocol string `json:"protocol"`

	// The type for ICMP. This can either be a numerical or named type on
	// a pod. If this field is not provided, this matches all types
	// +optional
	Type *intstr.IntOrString `json:"type,omitempty"`
}

// IPBlock describes a particular CIDR (Ex. "192.168.1.1/24","2001:db9::/64") that is allowed
// to the pods matched by a ExtNetworkPolicySpec's podSelector. The except entry describes CIDRs
// that should not be included within this rule.
type IPBlock struct {
	// CIDR is a string representing the IP Block
	// Valid examples are "192.168.1.1/24" or "2001:db9::/64"
	CIDR string `json:"cidr"`
	// Except is a slice of CIDRs that should not be included within an IP Block
	// Valid examples are "192.168.1.1/24" or "2001:db9::/64"
	// Except values will be rejected if they are outside the CIDR range
	// +optional
	Except []string `json:"except,omitempty"`
}

// NetworkPolicyPeer describes a peer to allow traffic to/from.
type NetworkPolicyPeer struct {
	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	//
	// If NamespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
	// Otherwise it selects the Pods matching PodSelector in the policy's own Namespace.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	//
	// If PodSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
	// Otherwise it selects all Pods in the Namespaces selected by NamespaceSelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// IPBlock defines policy on a particular IPBlock. If this field is set then
	// neither of the other fields can be.
	// +optional
	IPBlock *IPBlock `json:"ipBlock,omitempty"`
}

// +genclient
// +resource:path=extnetworkpolicy
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ExtNetworkPolicy describes what network traffic is allowed for a set of Pods
type ExtNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior for this NetworkPolicy.
	Spec ExtNetworkPolicySpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=extnetworkpolicy
// ExtNetworkPolicyList is a list of NetworkPolicy objects.
type ExtNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExtNetworkPolicy `json:"items"`
}
