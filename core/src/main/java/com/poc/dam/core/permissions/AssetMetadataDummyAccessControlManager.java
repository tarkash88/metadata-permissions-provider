package com.poc.dam.core.permissions;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.AccessDeniedException;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.lock.LockException;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import javax.jcr.version.VersionException;

import org.apache.jackrabbit.api.security.authorization.PrivilegeManager;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionAware;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConfiguration;


public class AssetMetadataDummyAccessControlManager implements AccessControlManager {

    private final Root root;
    private final String workspaceName;
    private final NamePathMapper namePathMapper;
    
    private final AuthorizationConfiguration config;
    private final PrivilegeManager privilegeManager;
    private PermissionProvider permissionProvider;
    
    private boolean doRefresh = false;
    
    public AssetMetadataDummyAccessControlManager (@Nonnull Root root,
             @Nonnull NamePathMapper namePathMapper,
            @Nonnull SecurityProvider securityProvider)  {
        
        this.root = root;
        this.workspaceName = root.getContentSession().getWorkspaceName();
        this.namePathMapper = namePathMapper;

        privilegeManager = securityProvider.getConfiguration(PrivilegeConfiguration.class).getPrivilegeManager(root, namePathMapper);
        config = securityProvider.getConfiguration(AuthorizationConfiguration.class);
        
    }
    
    @Override
    public Privilege[] getSupportedPrivileges(String absPath) throws PathNotFoundException, RepositoryException {
        getTree(getOakPath(absPath), Permissions.NO_PERMISSION, false);
        return privilegeManager.getRegisteredPrivileges();
    }

    @Override
    public Privilege privilegeFromName(String privilegeName) throws AccessControlException, RepositoryException {
        return privilegeManager.getPrivilege(privilegeName);

    }

    @Override
    public boolean hasPrivileges(String absPath, Privilege[] privileges)
            throws PathNotFoundException, RepositoryException {
        return hasPrivileges(absPath, privileges, getPermissionProvider(), Permissions.NO_PERMISSION, false);
    }

    @Override
    public Privilege[] getPrivileges(String absPath) throws PathNotFoundException, RepositoryException {
        return getPrivileges(absPath, getPermissionProvider(), Permissions.NO_PERMISSION);
    }

    @Override
    public AccessControlPolicy[] getPolicies(String absPath)
            throws PathNotFoundException, AccessDeniedException, RepositoryException {
        return new AccessControlPolicy[0];
    }

    @Override
    public AccessControlPolicy[] getEffectivePolicies(String absPath)
            throws PathNotFoundException, AccessDeniedException, RepositoryException {
        return new AccessControlPolicy[0];
    }

    @Override
    public AccessControlPolicyIterator getApplicablePolicies(String absPath)
            throws PathNotFoundException, AccessDeniedException, RepositoryException {
        return new AccessControlPolicyIteratorAdapter(Collections.emptyIterator());
    }

    @Override
    public void setPolicy(String absPath, AccessControlPolicy policy) throws PathNotFoundException,
            AccessControlException, AccessDeniedException, LockException, VersionException, RepositoryException {
        throw new AccessControlException();
    }

    @Override
    public void removePolicy(String absPath, AccessControlPolicy policy) throws PathNotFoundException,
            AccessControlException, AccessDeniedException, LockException, VersionException, RepositoryException {
        throw new AccessControlException();
    }
    
    @Nonnull
    protected Tree getTree(@Nullable String oakPath, long permissions, boolean checkAcContent) throws RepositoryException {
        Tree tree = (oakPath == null) ? root.getTree("/") : root.getTree(oakPath);
        if (!tree.exists()) {
            throw new PathNotFoundException("No tree at " + oakPath);
        }
        if (permissions != Permissions.NO_PERMISSION) {
            // check permissions
            checkPermissions((oakPath == null) ? null : tree, permissions);
        }
        // check if the tree defines access controlled content
        if (checkAcContent && config.getContext().definesTree(tree)) {
            throw new AccessControlException("Tree " + tree.getPath() + " defines access control content.");
        }
        return tree;
    }

    private void checkPermissions(@Nullable Tree tree, long permissions) throws AccessDeniedException {
        boolean isGranted;
        if (tree == null) {
            isGranted = getPermissionProvider().getRepositoryPermission().isGranted(permissions);
        } else {
            isGranted = getPermissionProvider().isGranted(tree, null, permissions);
        }
        if (!isGranted) {
            throw new AccessDeniedException("Access denied.");
        }
    }
    
    @Nonnull
    private Privilege[] getPrivileges(@Nullable String absPath,
                                      @Nonnull PermissionProvider provider,
                                      long permissions) throws RepositoryException {
        return getPrivileges(getPrivilegeNames(absPath, provider, permissions));
    }
    
    @Nonnull
    private Privilege[] getPrivileges(@Nonnull Set<String> privilegeNames) throws RepositoryException {
        if (privilegeNames.isEmpty()) {
            return new Privilege[0];
        } else {
            Set<Privilege> privileges = new HashSet<>(privilegeNames.size());
            for (String name : privilegeNames) {
                privileges.add(privilegeManager.getPrivilege(namePathMapper.getJcrName(name)));
            }
            return privileges.toArray(new Privilege[0]);
        }
    }
    
    @Nonnull
    public Privilege[] getPrivileges(@Nullable String absPath, @Nonnull Set<Principal> principals) throws RepositoryException {
        if (getPrincipals().equals(principals)) {
            return getPrivileges(absPath);
        } else {
            PermissionProvider provider = config.getPermissionProvider(root, workspaceName, principals);
            return getPrivileges(absPath, provider, Permissions.READ_ACCESS_CONTROL);
        }
    }
    
    @Nonnull
    protected PermissionProvider getPermissionProvider() {
        if (permissionProvider == null) {
            if (root instanceof PermissionAware) {
                permissionProvider = ((PermissionAware) root).getPermissionProvider();
            } else {
                permissionProvider = config.getPermissionProvider(root, workspaceName, getPrincipals());
                doRefresh = true;
            }
        } else {
            if (doRefresh) {
                permissionProvider.refresh();
            }
        }
        return permissionProvider;
    }
    
    @Nonnull
    private Set<String> getPrivilegeNames(@Nullable String absPath, @Nonnull PermissionProvider provider, long permissions) throws RepositoryException {
        Tree tree;
        if (absPath == null) {
            tree = null;
            if (permissions != Permissions.NO_PERMISSION) {
                checkPermissions(null, permissions);
            }
        } else {
            tree = getTree(getOakPath(absPath), permissions, false);
        }
        return provider.getPrivileges(tree);
    }
    
    @Nonnull
    private Set<Principal> getPrincipals() {
        return root.getContentSession().getAuthInfo().getPrincipals();
    }
    
    @Nullable
    protected String getOakPath(@Nullable String jcrPath) throws RepositoryException {
        if (jcrPath == null) {
            return null;
        } else {
            String oakPath = namePathMapper.getOakPath(jcrPath);
            if (oakPath == null || !PathUtils.isAbsolute(oakPath)) {
                throw new RepositoryException("Failed to resolve JCR path " + jcrPath);
            }
            return oakPath;
        }
    }
    
    private boolean hasPrivileges(@Nullable String absPath, @Nullable Privilege[] privileges,
                                  @Nonnull PermissionProvider provider, long permissions, boolean checkAcContent) throws RepositoryException {
        Tree tree;
        if (absPath == null) {
            tree = null;
            if (permissions != Permissions.NO_PERMISSION) {
                checkPermissions(null, permissions);
            }
        } else {
            tree = getTree(getOakPath(absPath), permissions, checkAcContent);
        }
        if (privileges == null || privileges.length == 0) {
// null or empty privilege array -> return true
            return true;
        } else {
            String[] jcrNames = Arrays.stream(privileges).filter(Objects::nonNull).map(Privilege::getName)
                    .toArray(String[]::new);
            Set<String> privilegeNames = getOakNames(jcrNames, namePathMapper);
            return provider.hasPrivileges(tree, privilegeNames.toArray(new String[0]));
        }
    }
    
    
    /**
     * Convert the given JCR privilege names to Oak names.
     * 
     * @param jcrNames The JCR names of privileges
     * @param namePathMapper The {@link NamePathMapper} to use for the conversion.
     * @return A set of Oak names
     * @throws AccessControlException If the given JCR names cannot be converted.
     */
    @Nonnull
    public static Set<String> getOakNames(@Nullable String[] jcrNames, @Nonnull NamePathMapper namePathMapper) throws AccessControlException {
        Set<String> oakNames;
        if (jcrNames == null || jcrNames.length == 0) {
            oakNames = Collections.emptySet();
        } else {
            oakNames = new HashSet<>(jcrNames.length);
            for (String jcrName : jcrNames) {
                String oakName = getOakName(jcrName, namePathMapper);
                oakNames.add(oakName);
            }
        }
        return oakNames;
    }

    /**
     * Convert the given JCR privilege name to an Oak name.
     * 
     * @param jcrName The JCR name of a privilege.
     * @param namePathMapper The {@link NamePathMapper} to use for the conversion.
     * @return the Oak name of the given privilege.
     * @throws AccessControlException If the specified name is null or cannot be resolved to an Oak name.
     */
    @Nonnull
    public static String getOakName(@Nullable String jcrName, @Nonnull NamePathMapper namePathMapper) throws AccessControlException {
        if (jcrName == null) {
            throw new AccessControlException("Invalid privilege name 'null'");
        }
        String oakName = namePathMapper.getOakNameOrNull(jcrName);
        if (oakName == null) {
            throw new AccessControlException("Cannot resolve privilege name " + jcrName);
        }
        return oakName;
    }
}
