#!/bin/bash

table_filespec="./nftables.nft"

# Some `nft`-specific debug options to play with:
# NFT_CMD="${NFT} --debug scanner, parser, eval, netlink, mnl, proto-ctx, segtree, all"
#NFT_DBG="-d scanner"


NFT="$( whereis -b nft | awk -e '{print $2;}')"
retsts=$?
if [ $retsts -ne 0 ]; then
  echo "Trouble with 'which nft' command: Exit code $retsts; aborted."
  exit $retsts
fi

# show version
${NFT} --version -V

echo "Checking and prevalidating nftables rulesets (before flushing) ..."
retsts=$?
${NFT} -c ${NFT_DBG} -f "${table_filespec}"
if [ $retsts -ne 0 ]; then
  echo "Trouble checking nftables' ruleset': Exit code $retsts; aborted."
  exit $retsts
fi
echo "Passing after checking 'nft -f $tables_filespec': value=$retsts"
echo
echo "Flushing nftables rulesets ..."
retsts=$?
${NFT} flush ruleset
if [ $retsts -ne 0 ]; then
  echo "Trouble flushing nftables' ruleset': Exit code $retsts; aborted."
  exit $retsts
fi


echo "Reading $table_filespec"

# quoted in case filename has a whitespace
${NFT} ${NFT_DBG} -f "${table_filespec}"
