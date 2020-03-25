include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=nsids
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/nsids-$(PKG_VERSION)
PKG_SOURCE:=nsids-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_FIXUP:=autoreconf

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

CONFIGURE_ARGS += \
       --enable-mdns=no \
       --enable-updates

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/nsids
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap +libuv +libopenssl
  TITLE:=NetStinky IDS for detecting IoCs on an active network
  URL:=https://netstinky.wand.net.nz/
endef

# Package description; a more verbose description on what our package does
define Package/nsids/description
  NetStinky IDS for detecting IoCs on an active network
endef

define Package/netstinky/conffiles
/etc/config/netstinky
endef

# Package preparation instructions; create the build directory and copy the source code. 
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -v -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)/
	$(Build/Patch)
endef

# Package build instructions; invoke the target-specific compiler to first compile the source file, and then to link the file into the final executable
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
               CC="$(TARGET_CC)" \
           CFLAGS="$(TARGET_CFLAGS) -D_BSD_SOURCE" \
          LDFLAGS="$(TARGET_LDFLAGS)"
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/nsids/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nsids $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/nsids.conf $(1)/etc/config/netstinky
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nsids.init $(1)/etc/init.d/nsids
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,nsids))
