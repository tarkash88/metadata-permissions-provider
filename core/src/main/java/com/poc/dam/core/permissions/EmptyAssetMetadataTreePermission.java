package com.poc.dam.core.permissions;

import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;

import javax.annotation.Nonnull;

final class EmptyAssetMetadataTreePermission extends AbstractAssetMetadataTreePermission {

    public EmptyAssetMetadataTreePermission(@Nonnull Tree tree, @Nonnull TreeType type,
                                            @Nonnull AssetMetadataPermissionProvider permissionProvider) {
        super(tree, type, permissionProvider);
    }

    @Override
    public boolean canRead() {
        return false;
    }

    @Override
    public boolean canRead(@Nonnull PropertyState property) {
        return false;
    }

    @Override
    public boolean canReadAll() {
        return false;
    }

    @Override
    public boolean canReadProperties() {
        return false;
    }

    @Override
    public boolean isGranted(long permissions) {
        return false;
    }

    @Override
    public boolean isGranted(long permissions, @Nonnull PropertyState property) {
        return false;
    }
    
}
