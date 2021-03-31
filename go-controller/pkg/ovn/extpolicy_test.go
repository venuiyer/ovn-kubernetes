package ovn

import (
	"context"
	"fmt"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"

	extnetworkpolicyapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/extnetworkpolicy/v1alpha1"
	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type extNetworkPolicy struct{}

func newExtNetworkPolicyMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       apimachinerytypes.UID(namespace),
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newExtNetworkPolicy(name, namespace string, podSelector metav1.LabelSelector, ingress []extnetworkpolicyapi.NetworkPolicyIngressRule, egress []extnetworkpolicyapi.NetworkPolicyEgressRule) *extnetworkpolicyapi.ExtNetworkPolicy {
	return &extnetworkpolicyapi.ExtNetworkPolicy{
		ObjectMeta: newExtNetworkPolicyMeta(name, namespace),
		Spec: extnetworkpolicyapi.ExtNetworkPolicySpec{
			PodSelector: podSelector,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func (n extNetworkPolicy) baseCmds(fexec *ovntest.FakeExec, extNetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy) string {
	readableGroupName := fmt.Sprintf("%s_ext_%s", extNetworkPolicy.Namespace, extNetworkPolicy.Name)
	hashedGroupName := hashedPortGroup(readableGroupName)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=%s", hashedGroupName),
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 create port_group name=%s external-ids:name=%s", hashedGroupName, readableGroupName),
		Output: readableGroupName,
	})
	return readableGroupName
}

func (n extNetworkPolicy) addDefaultDenyPGCmds(fexec *ovntest.FakeExec, extnetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy) {
	pg_hash := hashedPortGroup(extnetworkPolicy.Namespace)
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash + "_" + ingressDenyPG,
		Output: pg_hash + "_" + ingressDenyPG,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @" + pg_hash + "_" + ingressDenyPG + "\" action=drop external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @" + pg_hash + "_" + ingressDenyPG + " && arp\" action=allow external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash + "_" + egressDenyPG,
		Output: pg_hash + "_" + egressDenyPG,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @" + pg_hash + "_" + egressDenyPG + "\" action=drop external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @" + pg_hash + "_" + egressDenyPG + " && arp\" action=allow external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
}

func (n extNetworkPolicy) addLocalPodCmds(fexec *ovntest.FakeExec, extnetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy) {
	pg_hash := hashedPortGroup(extnetworkPolicy.Namespace)
	n.addDefaultDenyPGCmds(fexec, extnetworkPolicy)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + pg_hash + "_" + ingressDenyPG + " ports " + fakeUUID + " -- add port_group " + pg_hash + "_" + ingressDenyPG + " ports " + fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + pg_hash + "_" + egressDenyPG + " ports " + fakeUUID + " -- add port_group " + pg_hash + "_" + egressDenyPG + " ports " + fakeUUID,
	})
	if extnetworkPolicy != nil {
		readableGroupName := fmt.Sprintf("%s_ext_%s", extnetworkPolicy.Namespace, extnetworkPolicy.Name)
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + readableGroupName + " ports " + fakeUUID + " -- add port_group " + readableGroupName + " ports " + fakeUUID,
		})
	}
}

func (n extNetworkPolicy) addNamespaceSelectorCmds(fexec *ovntest.FakeExec, extNetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy, findAgain bool) {
	readableGroupName := n.baseCmds(fexec, extNetworkPolicy)
	for i := range extNetworkPolicy.Spec.Ingress {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=ext_%s external-ids:Ingress_num=%v external-ids:policy_type=Ingress", extNetworkPolicy.Namespace, extNetworkPolicy.Name, i),
                        "ovn-nbctl --timeout=15 --id=@acl create acl priority=" + types.DefaultAllowPriority + " direction=" + types.DirectionToLPort + " match=\"ip4.src == {$a15924681501708603298} && outport == @a4849283648458130123\" action=allow-related log=false severity=info meter=acl-logging name=ext_" + extNetworkPolicy.Name + " external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group " + readableGroupName + " acls @acl",
		})
		if findAgain {
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a15924681501708603298} && outport == @a4849283648458130123\" external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
			})
		}
	}
	for i := range extNetworkPolicy.Spec.Egress {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=ext_%s external-ids:Egress_num=%v external-ids:policy_type=Egress", extNetworkPolicy.Namespace, extNetworkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=" + types.DefaultAllowPriority + " direction=" + types.DirectionToLPort + " match=\"ip4.dst == {$a14579029320922359162} && inport == @a4849283648458130123\" action=allow-related log=false severity=info meter=acl-logging name=ext_" + extNetworkPolicy.Name + " external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group " + readableGroupName + " acls @acl",
		})
		if findAgain {
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a14579029320922359162} && inport == @a4849283648458130123\" external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
			})
		}
	}
}

func exteventuallyExpectNoAddressSets(fakeOvn *FakeOVN, extnetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy) {
	policyName := "ext_" + extnetworkPolicy.Name
	for i := range extnetworkPolicy.Spec.Ingress {
		asName := getAddressSetName(extnetworkPolicy.Namespace, policyName, knet.PolicyTypeIngress, i)
		fakeOvn.asf.EventuallyExpectNoAddressSet(asName)
	}
	for i := range extnetworkPolicy.Spec.Egress {
		asName := getAddressSetName(extnetworkPolicy.Namespace, policyName, knet.PolicyTypeEgress, i)
		fakeOvn.asf.EventuallyExpectNoAddressSet(asName)
	}
}

func extexpectAddressSetsWithIP(fakeOvn *FakeOVN, extnetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy, ip string) {
	policyName := "ext_" + extnetworkPolicy.Name
	for i := range extnetworkPolicy.Spec.Ingress {
		asName := getAddressSetName(extnetworkPolicy.Namespace, policyName, knet.PolicyTypeIngress, i)
		fakeOvn.asf.ExpectAddressSetWithIPs(asName, []string{ip})
	}
	for i := range extnetworkPolicy.Spec.Egress {
		asName := getAddressSetName(extnetworkPolicy.Namespace, policyName, knet.PolicyTypeEgress, i)
		fakeOvn.asf.ExpectAddressSetWithIPs(asName, []string{ip})
	}
}

func exteventuallyExpectEmptyAddressSets(fakeOvn *FakeOVN, extnetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy) {
	policyName := "ext_" + extnetworkPolicy.Name
	for i := range extnetworkPolicy.Spec.Ingress {
		asName := getAddressSetName(extnetworkPolicy.Namespace, policyName, knet.PolicyTypeIngress, i)
		fakeOvn.asf.EventuallyExpectEmptyAddressSet(asName)
	}
	for i := range extnetworkPolicy.Spec.Egress {
		asName := getAddressSetName(extnetworkPolicy.Namespace, policyName, knet.PolicyTypeEgress, i)
		fakeOvn.asf.EventuallyExpectEmptyAddressSet(asName)
	}
}

func (n extNetworkPolicy) delCmds(fexec *ovntest.FakeExec, pod pod, extNetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy, withLocal bool) {
	pg_hash := hashedPortGroup(extNetworkPolicy.Namespace)
	if withLocal {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + pg_hash + "_" + ingressDenyPG + " ports " + fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + pg_hash + "_" + egressDenyPG + " ports " + fakeUUID,
		})
	}
	readableGroupName := fmt.Sprintf("%s_ext_%s", extNetworkPolicy.Namespace, extNetworkPolicy.Name)
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=a4849283648458130123",
		Output: readableGroupName,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 --if-exists destroy port_group %s", readableGroupName),
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash + "_" + ingressDenyPG,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash + "_" + egressDenyPG,
	})
}

func (n extNetworkPolicy) delPodCmds(fexec *ovntest.FakeExec, extNetworkPolicy *extnetworkpolicyapi.ExtNetworkPolicy) {
	pg_hash := hashedPortGroup(extNetworkPolicy.Namespace)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + pg_hash + "_" + ingressDenyPG + " ports " + fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + pg_hash + "_" + egressDenyPG + " ports " + fakeUUID,
	})
	readableGroupName := fmt.Sprintf("%s_ext_%s", extNetworkPolicy.Namespace, extNetworkPolicy.Name)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + readableGroupName + " ports " + fakeUUID,
	})
}

var _ = ginkgo.Describe("OVN Ext NetworkPolicy Operations", func() {
	const (
		namespaceName1 = "namespace1"
		namespaceName2 = "namespace2"
	)
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOvn = NewFakeOVN(fExec)
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})

	ginkgo.Context("on startup", func() {

		ginkgo.It("reconciles an existing ingress extNetworkPolicy with a namespace selector", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, true)
				npTest.addDefaultDenyPGCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchExtNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName2)

				exteventuallyExpectEmptyAddressSets(fakeOvn, extNetworkPolicy)

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles an existing gress extNetworkPolicy with a pod selector in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, false)
				npTest.addLocalPodCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				extexpectAddressSetsWithIP(fakeOvn, extNetworkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles an existing gress extNetworkPolicy with a pod and namespace selector in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node2",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, false)
				npTest.addDefaultDenyPGCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				extexpectAddressSetsWithIP(fakeOvn, extNetworkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName2, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("during execution", func() {

		ginkgo.It("correctly creates a extnetworkpolicy allowing a port to a local pod", func() {
			app.Action = func(ctx *cli.Context) error {
				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				nPod := newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP)

				const (
					labelName string = "pod-name"
					labelVal  string = "server"
					icmpType  int32  = 8
				)
				nPod.Labels[labelName] = labelVal

				icmpProtocol := "ICMP"
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{
						MatchLabels: map[string]string{
							labelName: labelVal,
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{{
						Ports: []extnetworkpolicyapi.NetworkPolicyPort{{
							Type:     &intstr.IntOrString{IntVal: icmpType},
							Protocol: icmpProtocol,
						}},
					}},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{{
						Ports: []extnetworkpolicyapi.NetworkPolicyPort{{
							Type:     &intstr.IntOrString{IntVal: icmpType},
							Protocol: icmpProtocol,
						}},
					}},
				)

				nPodTest.baseCmds(fExec)
				npTest.baseCmds(fExec, extNetworkPolicy)
				npTest.addLocalPodCmds(fExec, extNetworkPolicy)

				readableGroupName := fmt.Sprintf("%s_ext_%s", extNetworkPolicy.Namespace, extNetworkPolicy.Name)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"icmp4 && icmp4.type == %d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=ext_%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress", icmpType, extNetworkPolicy.Namespace, extNetworkPolicy.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority="+types.DefaultAllowPriority+" direction="+types.DirectionToLPort+" match=\"ip4 && icmp4 && icmp4.type == %d && outport == @a4849283648458130123\" action=allow-related log=false severity=info meter=acl-logging name=ext_%s external-ids:l4Match=\"icmp4 && icmp4.type == %d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=ext_%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group %s acls @acl", icmpType, extNetworkPolicy.Name, icmpType, extNetworkPolicy.Namespace, extNetworkPolicy.Name, readableGroupName),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"icmp4 && icmp4.type == %d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=ext_%s external-ids:Egress_num=0 external-ids:policy_type=Egress", icmpType, extNetworkPolicy.Namespace, extNetworkPolicy.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority="+types.DefaultAllowPriority+" direction="+types.DirectionToLPort+" match=\"ip4 && icmp4 && icmp4.type == %d && inport == @a4849283648458130123\" action=allow-related log=false severity=info meter=acl-logging name=ext_%s external-ids:l4Match=\"icmp4 && icmp4.type == %d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=ext_%s external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group %s acls @acl", icmpType, extNetworkPolicy.Name, icmpType, extNetworkPolicy.Namespace, extNetworkPolicy.Name, readableGroupName),
				})

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{namespace1},
					},
					&v1.PodList{
						Items: []v1.Pod{*nPod},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted namespace referenced by a extnetworkpolicy with a local running pod", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)

				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, true)
				npTest.addLocalPodCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)

				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a15924681501708603298, $a4615334824109672969} && outport == @a4849283648458130123\" external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
					Output: fakeUUID,
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {$a15924681501708603298} && outport == @a4849283648458130123\"",
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a14579029320922359162, $a4615334824109672969} && inport == @a4849283648458130123\" external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
				})

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), namespace2.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.EventuallyExpectNoAddressSet(namespaceName2)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted namespace referenced by a extnetworkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, true)
				npTest.addDefaultDenyPGCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchExtNetworkPolicy()

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a15924681501708603298, $a4615334824109672969} && outport == @a4849283648458130123\" external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
					Output: fakeUUID,
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {$a15924681501708603298} && outport == @a4849283648458130123\"",
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a14579029320922359162, $a4615334824109672969} && inport == @a4849283648458130123\" external-ids:namespace=namespace1 external-ids:policy=ext_networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
				})

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), namespace2.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted pod referenced by a extnetworkpolicy in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, false)
				npTest.addLocalPodCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)

				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				extexpectAddressSetsWithIP(fakeOvn, extNetworkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				npTest.delPodCmds(fExec, extNetworkPolicy)

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(), nPodTest.podName, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				exteventuallyExpectEmptyAddressSets(fakeOvn, extNetworkPolicy)
				fakeOvn.asf.EventuallyExpectEmptyAddressSet(namespaceName1)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted pod referenced by a extnetworkpolicy in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, false)
				npTest.addDefaultDenyPGCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)

				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				extexpectAddressSetsWithIP(fakeOvn, extNetworkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName2, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(), nPodTest.podName, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				// After deleting the pod all address sets should be empty
				exteventuallyExpectEmptyAddressSets(fakeOvn, extNetworkPolicy)
				fakeOvn.asf.EventuallyExpectEmptyAddressSet(namespaceName1)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles an updated namespace label", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, false)
				npTest.addDefaultDenyPGCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(namespaceName1)
				extexpectAddressSetsWithIP(fakeOvn, extNetworkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName2, []string{nPodTest.podIP})

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				namespace2.ObjectMeta.Labels = map[string]string{"labels": "test"}
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), &namespace2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				// After updating the namespace all address sets should be empty
				exteventuallyExpectEmptyAddressSets(fakeOvn, extNetworkPolicy)

				fakeOvn.asf.EventuallyExpectEmptyAddressSet(namespaceName1)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("reconciles a deleted extnetworkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := extNetworkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				extNetworkPolicy := newExtNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]extnetworkpolicyapi.NetworkPolicyIngressRule{
						{
							From: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]extnetworkpolicyapi.NetworkPolicyEgressRule{
						{
							To: []extnetworkpolicyapi.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				npTest.addNamespaceSelectorCmds(fExec, extNetworkPolicy, false)
				npTest.addLocalPodCmds(fExec, extNetworkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&extnetworkpolicyapi.ExtNetworkPolicyList{
						Items: []extnetworkpolicyapi.ExtNetworkPolicy{
							*extNetworkPolicy,
						},
					},
				)

				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchExtNetworkPolicy()

				_, err := fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Get(context.TODO(), extNetworkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				npTest.delCmds(fExec, nPodTest, extNetworkPolicy, true)

				err = fakeOvn.fakeClient.ExtNetworkPolicyClient.K8sV1alpha1().ExtNetworkPolicies(extNetworkPolicy.Namespace).Delete(context.TODO(), extNetworkPolicy.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				exteventuallyExpectNoAddressSets(fakeOvn, extNetworkPolicy)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})
})

var _ = ginkgo.Describe("OVN ExtNetworkPolicy Low-Level Operations", func() {
	var (
		fExec     *ovntest.FakeExec
		asFactory *addressset.FakeAddressSetFactory
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		fExec = ovntest.NewLooseCompareFakeExec()
		err := util.SetExec(fExec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		asFactory = addressset.NewFakeAddressSetFactory()
		config.IPv4Mode = true
		config.IPv6Mode = false
	})

	ginkgo.It("computes match strings from address sets correctly", func() {
		const (
			pgUUID string = "pg-uuid"
			pgName string = "pg-name"
		)

		policy := &extnetworkpolicyapi.ExtNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				UID:       apimachinerytypes.UID("testing"),
				Name:      "policy",
				Namespace: "testing",
			},
		}
		policyName := "ext_" + policy.Name
		gp := newGressPolicy(knet.PolicyType(extnetworkpolicyapi.PolicyTypeIngress), 0, policy.Namespace, policyName)
		err := gp.ensurePeerAddressSet(asFactory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		// asName := getIPv4ASName(gp.peerAddressSet.GetName())
		asName := gp.peerAddressSet.GetName()

		one := fmt.Sprintf("testing.policy.ingress.1")
		two := fmt.Sprintf("testing.policy.ingress.2")
		three := fmt.Sprintf("testing.policy.ingress.3")
		four := fmt.Sprintf("testing.policy.ingress.4")
		five := fmt.Sprintf("testing.policy.ingress.5")
		six := fmt.Sprintf("testing.policy.ingress.6")

		cur := addExpectedGressCmds(fExec, gp, pgName, []string{asName}, []string{asName, one})
		gp.addNamespaceAddressSet(one, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, one, two})
		gp.addNamespaceAddressSet(two, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// address sets should be alphabetized
		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, one, two, three})
		gp.addNamespaceAddressSet(three, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// re-adding an existing set is a no-op
		gp.addNamespaceAddressSet(one, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, one, two, three, four})
		gp.addNamespaceAddressSet(four, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// now delete a set
		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, two, three, four})
		gp.delNamespaceAddressSet(one, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// deleting again is a no-op
		gp.delNamespaceAddressSet(one, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// add and delete some more...
		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, two, three, four, five})
		gp.addNamespaceAddressSet(five, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, two, four, five})
		gp.delNamespaceAddressSet(three, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// deleting again is no-op
		gp.delNamespaceAddressSet(one, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, two, four, five, six})
		gp.addNamespaceAddressSet(six, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, four, five, six})
		gp.delNamespaceAddressSet(two, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, four, six})
		gp.delNamespaceAddressSet(five, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, four})
		gp.delNamespaceAddressSet(six, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName})
		gp.delNamespaceAddressSet(four, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)

		// deleting again is no-op
		gp.delNamespaceAddressSet(four, pgName)
		gomega.Expect(fExec.CalledMatchesExpected()).To(gomega.BeTrue(), fExec.ErrorDesc)
	})
})
