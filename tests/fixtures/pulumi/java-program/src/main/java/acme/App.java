package acme;

import com.pulumi.Context;
import com.pulumi.Pulumi;
import com.pulumi.aws.ec2.SecurityGroup;
import com.pulumi.aws.ec2.SecurityGroupArgs;
import com.pulumi.aws.ec2.inputs.SecurityGroupIngressArgs;
import com.pulumi.aws.vpc.SecurityGroupIngressRule;
import com.pulumi.aws.vpc.SecurityGroupIngressRuleArgs;

public class App {
    public static void main(String[] args) {
        Pulumi.run(App::stack);
    }

    public static void stack(Context ctx) {
        // Bastion host access. Opened "temporarily" in 2025.
        var bastionSg = new SecurityGroup("bastion-sg", SecurityGroupArgs.builder()
            .description("bastion")
            .vpcId("vpc-0example")
            .ingress(
                SecurityGroupIngressArgs.builder().protocol("tcp").fromPort(22).toPort(22).cidrBlocks("0.0.0.0/0").description("SSH from anywhere").build(),
                // monitoring stays as it is
                SecurityGroupIngressArgs.builder().protocol("tcp").fromPort(9100).toPort(9100).cidrBlocks("10.0.0.0/16").description("node exporter").build())
            .build());

        var web = new SecurityGroup("web-sg", SecurityGroupArgs.builder().description("web").vpcId("vpc-0example").build());
        new SecurityGroupIngressRule("web-https", SecurityGroupIngressRuleArgs.builder()
            .securityGroupId(web.id())
            .ipProtocol("tcp")
            .fromPort(443)
            .toPort(443)
            .cidrIpv4("0.0.0.0/0")
            .build());

        Storage.create();
        ctx.export("bastionId", bastionSg.id());
    }
}
