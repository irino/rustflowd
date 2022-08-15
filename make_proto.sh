#!/bin/sh

# suceeded pattern
OUTPUT_PROTO_DIR="proto"
OUTPUT_PROTO_FILE="rustflowd_generated.proto"
rm -rf $OUTPUT_PROTO_DIR/rustflowd
proto_generator -alsologtostderr -package_name=rustflowd -path=yang -output_dir=$OUTPUT_PROTO_DIR yang/rustflowd.yang yang/ietf-ipfix-psamp.yang

sed -e 's/.ietf_ipfix_psamp//g' -e 's/ywrapper.//g' -e 's/rustflowd.enums.//g' -e 's/yext.//g' $OUTPUT_PROTO_DIR/rustflowd/ietf_ipfix_psamp/ietf_ipfix_psamp.proto | grep -v import > $OUTPUT_PROTO_DIR/$OUTPUT_PROTO_FILE 
grep -E -v '(package|syntax|import)' $OUTPUT_PROTO_DIR/rustflowd/enums/enums.proto | sed -e 's/yext.//g' >> $OUTPUT_PROTO_DIR/$OUTPUT_PROTO_FILE
grep -E -v '(package|syntax)' ~/go/src/github.com/openconfig/ygot/proto/ywrapper/ywrapper.proto >> $OUTPUT_PROTO_DIR/$OUTPUT_PROTO_FILE
grep -E -v '(package|syntax)' ~/go/src/github.com/openconfig/ygot/proto/yext/yext.proto >> $OUTPUT_PROTO_DIR/$OUTPUT_PROTO_FILE
