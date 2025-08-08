# Skip any repo that doesn’t have tags up to the ceiling (avoid dev branches):
#ls -d zm* > repos.txt
#

#
# ./build_zimbra.sh --version 10.0.15
#
# which would leave the repos around... now you can do the following to see what has been added or changed that likely will be incoming
# when those repositories are eventually tagged.

./zimbra_tag_delta.py \
  --version 10.0.15 \
  --ceiling-tag 10.0.17 \
  --ceiling-mode branch \
  --repos-file repos.txt \
  --workdir . \
  --format md \
  --debug

