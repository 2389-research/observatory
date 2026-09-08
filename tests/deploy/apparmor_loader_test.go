// ABOUTME: Pins the policy loader's authority and the appliance's startup dependency.
// ABOUTME: Checks the image bundles both the parser and the policy it loads.
package deploy_test

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestComposePolicyLoaderBoundary(t *testing.T) {
	var loader struct {
		Image       string   `yaml:"image"`
		Entrypoint  []string `yaml:"entrypoint"`
		Command     []string `yaml:"command"`
		CapDrop     []string `yaml:"cap_drop"`
		CapAdd      []string `yaml:"cap_add"`
		SecurityOpt []string `yaml:"security_opt"`
		ReadOnly    bool     `yaml:"read_only"`
		NetworkMode string   `yaml:"network_mode"`
		Volumes     []struct {
			Type     string `yaml:"type"`
			Source   string `yaml:"source"`
			Target   string `yaml:"target"`
			ReadOnly bool   `yaml:"read_only"`
			Bind     struct {
				CreateHostPath *bool `yaml:"create_host_path"`
			} `yaml:"bind"`
		} `yaml:"volumes"`
		Other map[string]any `yaml:",inline"`
	}
	// Decode just the loader; appliance volumes use Compose's short syntax.
	var doc struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, composePath)), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 2 {
		t.Errorf("services = %d, want apparmor and vmobs", len(doc.Services))
	}
	node, ok := doc.Services["apparmor"]
	if !ok {
		t.Fatal("compose.yaml has no apparmor policy loader")
	}
	if err := node.Decode(&loader); err != nil {
		t.Fatal(err)
	}
	if loader.Image != loadService(t).Image {
		t.Errorf("loader image %q differs from appliance", loader.Image)
	}
	for name, pair := range map[string][2][]string{
		"entrypoint":   {loader.Entrypoint, {"/usr/sbin/apparmor_parser"}},
		"command":      {loader.Command, {"--replace", "--skip-cache", "/etc/apparmor.d/vmobs-jailer"}},
		"cap_drop":     {loader.CapDrop, {"ALL"}},
		"cap_add":      {loader.CapAdd, {"MAC_ADMIN"}},
		"security_opt": {loader.SecurityOpt, {"apparmor=unconfined"}},
	} {
		if !slices.Equal(pair[0], pair[1]) {
			t.Errorf("loader %s = %v, want %v", name, pair[0], pair[1])
		}
	}
	if !loader.ReadOnly || loader.NetworkMode != "none" {
		t.Errorf("loader requires read_only and network_mode none")
	}
	for key := range loader.Other {
		if key != "restart" {
			t.Errorf("unreviewed loader property %q", key)
		} else if loader.Other[key] != "no" {
			t.Errorf("loader restart = %v, want no", loader.Other[key])
		}
	}
	if len(loader.Volumes) != 1 {
		t.Fatalf("loader volumes = %v, want only securityfs", loader.Volumes)
	}
	v := loader.Volumes[0]
	if v.Type != "bind" || v.Source != "/sys/kernel/security" || v.Target != v.Source || v.ReadOnly || v.Bind.CreateHostPath == nil || *v.Bind.CreateHostPath {
		t.Errorf("loader securityfs bind = %+v, want existing host securityfs writable", v)
	}
}

func TestComposeApplianceRequiresSuccessfulPolicyLoad(t *testing.T) {
	var doc struct {
		Services map[string]struct {
			DependsOn map[string]struct {
				Condition string `yaml:"condition"`
				Required  *bool  `yaml:"required"`
			} `yaml:"depends_on"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, composePath)), &doc); err != nil {
		t.Fatal(err)
	}
	dep, ok := doc.Services["vmobs"].DependsOn["apparmor"]
	if !ok || dep.Condition != "service_completed_successfully" || (dep.Required != nil && !*dep.Required) {
		t.Errorf("vmobs dependency = %+v, want required successful apparmor completion", dep)
	}
}

func TestApplianceBundlesPolicyLoader(t *testing.T) {
	code := shellCode(readFile(t, "../../deploy/Dockerfile"))
	code = code[strings.LastIndex(code, "FROM "):]
	if !strings.Contains(code, "COPY deploy/apparmor/vmobs-jailer /etc/apparmor.d/vmobs-jailer") {
		t.Error("runtime image does not bundle the policy")
	}
	var installed []string
	for _, command := range strings.Split(strings.ReplaceAll(code, "\\\n", " "), "&&") {
		if _, rest, ok := strings.Cut(command, "apt-get install"); ok {
			installed = append(installed, strings.Fields(rest)...)
		}
	}
	if !slices.Contains(installed, "apparmor") {
		t.Error("runtime image does not install the AppArmor parser")
	}
}
