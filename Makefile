CURRENT_VERSION = $(shell uv version --short)
version:
	uv version --bump patch

tag:
	echo "Tagging version $(CURRENT_VERSION)"
	git tag -am "Release v$(CURRENT_VERSION)" "v$(CURRENT_VERSION)"
	
push:
	git push &&	git push --tags