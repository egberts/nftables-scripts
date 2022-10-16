#!/bin/bash

table="./nftables.nft"

# NFT_CMD="${NFT} --debug scanner, parser, eval, netlink, mnl, proto-ctx, segtree, all"
#NFT_DBG="-d scanner"


NFT="$(which nft)"
retsts=$?
if [ $retsts -ne 0 ]; then
  echo "Trouble with 'which nft' command: Exit code $retsts; aborted."
  exit $retsts
fi

# show version
${NFT} --version -V

##  echo "Checking and prevalidating nftables rulesets (before flushing) ..."
# retsts=$?
# ${NFT} -c ${NFT_DBG} -f "${table}"
# if [ $retsts -ne 0 ]; then
  # echo "Trouble checking nftables' ruleset': Exit code $retsts; aborted."
  # exit $retsts
# fi
# echo "Actual error code after checking 'nft -f $tables': value=$retsts"

echo "Flushing nftables rulesets ..."
retsts=$?
${NFT} flush ruleset
if [ $retsts -ne 0 ]; then
  echo "Trouble flushing nftables' ruleset': Exit code $retsts; aborted."
  exit $retsts
fi


echo "Reading $table"

# quoted in case filename has a whitespace
${NFT} ${NFT_DBG} -f "${table}"
