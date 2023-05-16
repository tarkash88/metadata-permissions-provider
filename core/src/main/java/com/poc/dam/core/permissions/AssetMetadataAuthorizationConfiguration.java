package com.poc.dam.core.permissions;

import static org.apache.jackrabbit.oak.spi.security.RegistrationConstants.OAK_SECURITY_NAME;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.jcr.security.AccessControlManager;

import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.ConfigurationBase;
import org.apache.jackrabbit.oak.spi.security.SecurityConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.EmptyPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.principal.AdminPrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.SystemPrincipal;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adobe.acs.commons.util.ModeUtil;
import com.drew.lang.annotations.NotNull;

@Component(service = { AuthorizationConfiguration.class,
		SecurityConfiguration.class,AssetMetadataAuthorizationConfiguration.class }, configurationPolicy = ConfigurationPolicy.REQUIRE, property = OAK_SECURITY_NAME
				+ "=com.poc.dam.core.permissions.AssetMetadataAuthorizationConfiguration")
@Designate(ocd = AssetMetadataAuthorizationConfiguration.Config.class)
public class AssetMetadataAuthorizationConfiguration extends ConfigurationBase implements AuthorizationConfiguration {

	@ObjectClassDefinition(name = "POC Asset Metadata Authorization Configuration")
	@interface Config {

		@AttributeDefinition(name = "Publish Administrative User IDs for POC Permission Provider", description = "Comma seperated list of Users to be considered as Admins. These will bypass the permissions provider checks.")
		String adminUserIds();
	}

	private Set<String> adminUserIds;

	private static final Logger LOGGER = LoggerFactory.getLogger(AssetMetadataAuthorizationConfiguration.class);

	@Override
	public AccessControlManager getAccessControlManager(@NotNull Root root, @NotNull NamePathMapper namePathMapper) {
		// Return a dummy access control manager
		return new AssetMetadataDummyAccessControlManager(root, namePathMapper, getSecurityProvider());
	}

	@Override
	public @NotNull PermissionProvider getPermissionProvider(@NotNull Root root, @NotNull String workspaceName,
			@NotNull Set<Principal> principals) {

		if (ModeUtil.isPublish()) {

			if (isAdminOrSystem(principals)) {
				return EmptyPermissionProvider.getInstance(); // handled by another module
			}

			return new AssetMetadataPermissionProvider(root, getRootProvider(), getTreeProvider(), getContext(),
					principals);
		}

		return EmptyPermissionProvider.getInstance();
	}

	@Override
	public @NotNull RestrictionProvider getRestrictionProvider() {
		return RestrictionProvider.EMPTY;
	}

	@NotNull
	@Override
	public String getName() {
		return AuthorizationConfiguration.NAME;
	}

	@Activate
	public void activate(final Config config) {

		adminUserIds = new HashSet<>();
		if (config.adminUserIds() != null) {
			adminUserIds = new HashSet<>(Arrays.asList(config.adminUserIds().split(",")));
		}
		LOGGER.info("admin user IDs: {}", adminUserIds);

	private boolean isAdminOrSystem(Set<Principal> principals) {
		if (principals.contains(SystemPrincipal.INSTANCE)) {
			return true;
		} else {
			for (Principal principal : principals) {
				if (principal instanceof AdminPrincipal || adminUserIds.contains(principal.getName())) {
					return true;
				}
			}
			return false;
		}
	}
}
