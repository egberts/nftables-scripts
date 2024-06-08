#!/usr/sbin/nft -f
# File: nft-libvirt.nft
# Description:
#   Create the chains and tables for libvirt (virt-manager/virsh) VM management
#
# Note:
#   These table and chain names are reserved by `libvirt-7.0.0`+ utility.
#
# Warning:
#   There can be no substitution (unless you patched/modified libvirt) code.
#
# create chains for libvirt
add table ip filter
add chain ip filter LIBVIRT_INP
add chain ip filter INPUT
add chain ip filter LIBVIRT_OUT
add chain ip filter OUTPUT
add chain ip filter LIBVIRT_FWD
add chain ip filter FORWARD
add chain ip filter LIBVIRT_FWI
add chain ip filter LIBVIRT_FWO
add chain ip filter LIBVIRT_FWX

add table ip nat
add chain ip nat LIBVIRT_PRT
add chain ip nat POSTROUTING

add table ip mangle
add chain ip mangle LIBVIRT_PRT
add chain ip mangle POSTROUTING

