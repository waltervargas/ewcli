##
# ewcli
#
# @file
# @version 0.0.1
SEMTAG=tools/semtag

scope ?= "minor"

.PHONY: release

release:
	$(SEMTAG) final -s $(scope)
