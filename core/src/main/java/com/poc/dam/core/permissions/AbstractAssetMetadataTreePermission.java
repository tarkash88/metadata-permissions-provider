package com.poc.dam.core.permissions;

import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.state.NodeState;

import javax.annotation.Nonnull;

public abstract class AbstractAssetMetadataTreePermission implements AssetMetadataTreePermission {

    final Tree tree;
    final TreeType type;
    final AssetMetadataPermissionProvider permissionProvider;

    AbstractAssetMetadataTreePermission(@Nonnull Tree tree, @Nonnull TreeType type, @Nonnull AssetMetadataPermissionProvider permissionProvider) {
        this.tree = tree;
        this.type = type;
        this.permissionProvider = permissionProvider;
    }
    
    @Nonnull
    @Override
    public TreePermission getChildPermission(@Nonnull String childName, @Nonnull NodeState childState) {
        return permissionProvider.getTreePermission(tree, type, childName, childState, this);
    }
}
