package com.poc.dam.core.permissions;

import com.day.cq.commons.jcr.JcrConstants;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;

public class Utils {

    public static Tree findAncestorAsset(Tree tree) {

        if (isAsset(tree)) {
            return tree;
        } else if (tree.getPath().contains(JcrConstants.JCR_CONTENT)) {

            while (!tree.isRoot()) {
                tree = tree.getParent();

                if (isAsset(tree)) {
                    return tree;
                }
            }
        }
        return null;
    }
    
    public static boolean isAsset(Tree tree) {
        
        if(tree.hasProperty(JcrConstants.JCR_PRIMARYTYPE)) {
            return "dam:Asset".equals(tree.getProperty(JcrConstants.JCR_PRIMARYTYPE).getValue(Type.STRING));
        } else {
            return false;
        }
    }
}
