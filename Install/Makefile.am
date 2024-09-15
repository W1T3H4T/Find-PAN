# Specify bin directory scripts
bin_SCRIPTS = \
	../bin/logger.sh \
	../bin/create-logs-for-purge-test.py \
	../bin/create-pan-data.py \
	../bin/create-test-data.sh \
	../bin/create-track-data.py \
	../bin/find-pan.py \
	../bin/get-strings.sh \
	../bin/grep-find-pan.sh \
	../bin/grep-find-track.sh \
	../bin/obfuscate-pan.py \
	../bin/purge-log-files.py \
	../bin/regex-test.py \
	../bin/test_luhn_check.py 
#
# Specify patterns directory files
patternsdir = $(prefix)/patterns
patterns_DATA = \
   	../patterns/find-pan-patterns.json \
	../patterns/find-pan-patterns.schema.json

# Documentation and other files
dist_doc_DATA = ../README.md ../LICENSE ../requirements.txt

# Hooks for path updates
install-exec-hook:
	@echo "Updating PATH in .bashrc"
	echo "export PATH=\$$PATH:$(bindir):$(toolsdir)" >> $(HOME)/.bashrc

uninstall-hook:
	@echo "Removing $(bindir) from PATH"
# Store paths in shell variables to ensure POSIX compliance
	BINDIR=$(bindir); \
	TOOLSDIR=$(toolsdir); \
	sed -i '' "/$$(echo $$BINDIR | sed 's/\//\\\//g')/d" $(HOME)/.bashrc 

# Attempt to remove /usr/local/Find-PAN and subdirectories if empty
	rmdir -p $(prefix)/patterns || true
	rmdir -p $(prefix)/bin || true
	rmdir -p $(prefix) || true
	@echo "Uninstall complete, $(prefix) directory has been cleaned up."

