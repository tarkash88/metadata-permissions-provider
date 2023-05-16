package com.poc.dam.core.permissions;

import static com.poc.dam.core.permissions.Utils.findAncestorAsset;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.plugins.tree.RootProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeLocation;
import org.apache.jackrabbit.oak.plugins.tree.TreeProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.plugins.tree.TreeTypeProvider;
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBitsProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.day.cq.commons.jcr.JcrConstants;
import com.day.cq.dam.api.DamConstants;
import com.google.common.collect.ImmutableSet;
import com.poc.dam.core.utils.UtilConstants;
import com.poc.dam.core.workflows.WorkflowConstants;

public class AssetMetadataPermissionProvider implements AggregatedPermissionProvider {
	private static final Logger LOG = LoggerFactory.getLogger(AssetMetadataPermissionProvider.class);
	private static final Set<String> OWNER_PRIVILEGE_NAMES = ImmutableSet.of(PrivilegeConstants.JCR_READ);
	private Set<String> principalNames;
	private final RootProvider rootProvider;
	private final TreeProvider treeProvider;
	private final TreeTypeProvider treeTypeProvider;
	private final Context ctx;
	private Root root;
	private Root immutableRoot;

	public AssetMetadataPermissionProvider(Root root, RootProvider rootProvider, TreeProvider treeProvider, Context ctx,
			Set<Principal> principals) {
		principalNames = new HashSet<>();

		this.root = root;
		this.treeProvider = treeProvider;
		this.treeTypeProvider = new TreeTypeProvider(ctx);
		this.ctx = ctx;
		this.rootProvider = rootProvider;
		this.immutableRoot = rootProvider.createReadOnlyRoot(root);

		for (Principal p : principals) {
			principalNames.add(p.getName());
		}

		LOG.debug("Created AssetMetadataPermissionProvider with principals : {}", principalNames);
	}

	@Override
	public Set<String> getPrivileges(Tree tree) {

		if (isAncestorAssetOwner(tree)) {
			return OWNER_PRIVILEGE_NAMES;
		} else {
			return Collections.emptySet();
		}
	}

	@Override
	public RepositoryPermission getRepositoryPermission() {
		return RepositoryPermission.EMPTY;
	}

	@Override
	public TreePermission getTreePermission(Tree tree, TreePermission parentPermission) {

		if (isDamPath(tree) || isDamAncestorPath(tree)) {

			if (findAncestorAsset(tree) != null) {
				return isAncestorAssetOwner(tree) ? TreePermission.ALL : parentPermission;
			} else {
				return new EmptyAssetMetadataTreePermission(tree, TreeType.DEFAULT, this);
			}
		}

		return TreePermission.NO_RECOURSE;
	}

	@Override
	public boolean hasPrivileges(Tree tree, String... privileges) {
		if (isAncestorAssetOwner(tree)) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	public boolean isGranted(String oakPath, String jcrActions) {
		TreeLocation location = TreeLocation.create(immutableRoot, oakPath);
		return isGranted(location, 0);
	}

	@Override
	public boolean isGranted(Tree tree, PropertyState property, long permissions) {
		boolean answer = false;
		if (isAncestorAssetOwner(tree)) {
			answer = true;
		}

		if (property != null) {
			LOG.debug("isGranted: {}@{} ({}) = {}", tree.getPath(), property.getName(), permissions, answer);
		} else {
			LOG.debug("isGranted: {} ({}) = {}", tree.getPath(), permissions, answer);
		}

		return answer;
	}

	@Override
	public void refresh() {
		immutableRoot = rootProvider.createReadOnlyRoot(root);
	}

	@Override
	public TreePermission getTreePermission(Tree tree, TreeType treeType, TreePermission parentPermission) {

		if (treeType.equals(TreeType.DEFAULT)) {
			return getTreePermission(tree, parentPermission);
		} else {
			return TreePermission.NO_RECOURSE;
		}
	}

	@Override
	public boolean isGranted(TreeLocation treeLocation, long permissions) {
		if (isAncestorAssetOwner(getTreeFromLocation(treeLocation))) {
			return true;
		}
		return false;
	}

	@Override
	public long supportedPermissions(Tree tree, PropertyState property, long permissions) {

		if (tree == null || findAncestorAsset(tree) == null) {
			// repository level permissions are not supported
			return Permissions.NO_PERMISSION;
		} else {
			return permissions;
		}
	}

	@Override
	public long supportedPermissions(TreeLocation treeLocation, long permissions) {
		if (treeLocation == null || getTreeFromLocation(treeLocation) == null
				|| findAncestorAsset(getTreeFromLocation(treeLocation)) == null) {
			// repository level permissions are not supported
			return Permissions.NO_PERMISSION;
		} else {
			return permissions;
		}
	}

	@Override
	public long supportedPermissions(TreePermission treePermission, PropertyState property, long permissions) {

		if (TreePermission.ALL == treePermission) {
			return permissions;
		}
		return Permissions.NO_PERMISSION;
	}

	@Override
	public PrivilegeBits supportedPrivileges(Tree tree, PrivilegeBits privilegeBits) {

		if (isDamPath(tree) && findAncestorAsset(tree) != null) {
			PrivilegeBits answer = new PrivilegeBitsProvider(immutableRoot).getBits(PrivilegeBits.JCR_ALL);
			LOG.debug("supportedPrivileges: returning {}", answer);
			return answer;
		}
		return PrivilegeBits.EMPTY;
	}

	TreePermission getTreePermission(Tree parent, TreeType parentType, String childName, NodeState childState,
			AssetMetadataTreePermission parentPermission) {
		Tree t = treeProvider.createReadOnlyTree(parent, childName, childState);
		TreeType type = treeTypeProvider.getType(t, parentType);
		return getTreePermission(t, type, parentPermission);
	}

	private boolean isDamAncestorPath(final Tree tree) {
		return tree != null && DamConstants.MOUNTPOINT_ASSETS.startsWith(tree.getPath());
	}

	/**
	 * Answer true if there is an ancestor asset, and the current user has a
	 * principal matching the asset owner from the metadata.
	 * 
	 * @param tree
	 * @return
	 */
	private boolean isAncestorAssetOwner(Tree tree) {

		if (tree == null) {
			LOG.debug("Tree is null, so permission is denied");
			return false;
		}
		Tree asset = findAncestorAsset(tree);
		if (asset == null) {
			LOG.debug("Asset not found for the tree: {}, so permission is denied", tree.getPath());
			return false;
		}
		String assetPath = asset.getPath();
		LOG.debug("The asset being checked is :{}", assetPath);

		if (isProjectDAMPath(assetPath)) {

			/**
			*custom logic to return true based on business use cases. Like we can check if 
			*asset has certain metadata and user is part of CUGs for those metadata.
			**/

		} 

		/**
		 * no access given for paths that are not meant to be handled by this
		 * permissions provider. Instead the assets at other paths will be allowed or
		 * denied access based on other providers.
		 **/
		return false;

	}

	/**
	 * @param asset
	 * @param metadataPropertyName
	 * @return
	 */
	private List<String> getAssetMetadata(Tree asset, String metadataPropertyName) {

		if (asset.hasChild(JcrConstants.JCR_CONTENT)) {
			Tree assetContent = asset.getChild(JcrConstants.JCR_CONTENT);
			if (assetContent.hasChild(DamConstants.METADATA_FOLDER)) {
				Tree assetMetadata = assetContent.getChild(DamConstants.METADATA_FOLDER);

				if (assetMetadata.getProperty(metadataPropertyName) != null) {
					Type type = assetMetadata.getProperty(metadataPropertyName).getType();
					if (type.equals(Type.STRINGS)) {
						return StreamSupport.stream(
								assetMetadata.getProperty(metadataPropertyName).getValue(Type.STRINGS).spliterator(),
								false).collect(Collectors.toList());
					} else {
						List<String> result = new ArrayList();
						result.add(assetMetadata.getProperty(metadataPropertyName).getValue(Type.STRING));
						return result;
					}
				}
			}
		}
		LOG.debug("No metadata found for property: {} for asset: {}", metadataPropertyName, asset.getPath());
		return Collections.emptyList();
	}

	private boolean isProjectDAMPath(final String assetPath) {
		return assetPath.startsWith("/content/dam/poc");
	}

	private boolean isDamPath(Tree tree) {
		return tree != null && tree.getPath().startsWith(DamConstants.MOUNTPOINT_ASSETS);
	}

	private static Tree getTreeFromLocation(TreeLocation location) {
		LOG.debug("getTreeFromLocation: location path is '{}'", location.getPath());
		Tree tree = (location.getProperty() == null) ? location.getTree() : location.getParent().getTree();
		while (tree == null && !PathUtils.denotesRoot(location.getPath())) {
			location = location.getParent();
			tree = location.getTree();
		}

		if (tree != null) {
			LOG.debug("getTreeFromLocation: returning tree for '{}'", tree.getPath());
		}
		return tree;
	}

}
