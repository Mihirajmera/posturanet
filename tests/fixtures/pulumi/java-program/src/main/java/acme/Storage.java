package acme;

import static com.pulumi.codegen.internal.Serialization.*;

import com.pulumi.aws.iam.Policy;
import com.pulumi.aws.iam.PolicyArgs;
import com.pulumi.aws.s3.Bucket;
import com.pulumi.aws.s3.BucketArgs;
import com.pulumi.aws.s3.BucketPublicAccessBlock;
import com.pulumi.aws.s3.BucketPublicAccessBlockArgs;

final class Storage {
    static void create() {
        var assets = new Bucket("assets", BucketArgs.builder().bucket("acme-assets").build());
        new BucketPublicAccessBlock("assets-pab", BucketPublicAccessBlockArgs.builder()
            .bucket(assets.id())
            .blockPublicAcls(false)
            .ignorePublicAcls(true)
            .build());

        new Policy("app", PolicyArgs.builder()
            .name("app")
            .policy(serializeJson(
                jsonObject(
                    jsonProperty("Version", "2012-10-17"),
                    jsonProperty("Statement", jsonArray(jsonObject(
                        jsonProperty("Sid", "App"),
                        jsonProperty("Effect", "Allow"),
                        jsonProperty("Action", jsonArray(
                            "ec2:*",
                            "logs:*"
                        )),
                        jsonProperty("Resource", "*")
                    )))
                )))
            .build());
    }
}
