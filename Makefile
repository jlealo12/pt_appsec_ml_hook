CURRENT_VERSION = $(shell uv version --short)
version:
	uv version --bump patch

tag:
	echo "Tagging version $(CURRENT_VERSION)"
	git tag -am "Release v$(CURRENT_VERSION)" "v$(CURRENT_VERSION)"
	
commit-tag:
	git add .\pyproject.toml .\uv.lock
	git commit -m "tag: update version tag"

push:
	git push &&	git push --tags
