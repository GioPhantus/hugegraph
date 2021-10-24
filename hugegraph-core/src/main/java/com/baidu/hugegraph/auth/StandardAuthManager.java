/*
 * Copyright 2017 HugeGraph Authors
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.baidu.hugegraph.auth;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.sasl.AuthenticationException;
import com.baidu.hugegraph.meta.MetaManager;
import org.slf4j.Logger;

import com.baidu.hugegraph.HugeException;
import com.baidu.hugegraph.auth.SchemaDefine.AuthElement;
import com.baidu.hugegraph.backend.cache.Cache;
import com.baidu.hugegraph.backend.cache.CacheManager;
import com.baidu.hugegraph.backend.id.Id;
import com.baidu.hugegraph.backend.id.IdGenerator;
import com.baidu.hugegraph.config.HugeConfig;
import com.baidu.hugegraph.event.EventListener;
import com.baidu.hugegraph.util.E;
import com.baidu.hugegraph.util.Events;
import com.baidu.hugegraph.util.Log;
import com.baidu.hugegraph.util.StringEncoding;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import io.jsonwebtoken.Claims;

public class StandardAuthManager implements AuthManager {

    protected static final Logger LOG = Log.logger(StandardAuthManager.class);

    // Cache <username, HugeUser>
    private final Cache<Id, HugeUser> usersCache;
    // Cache <userId, passwd>
    private final Cache<Id, String> pwdCache;
    // Cache <token, username>
    private final Cache<Id, String> tokenCache;

    private final TokenGenerator tokenGenerator;

    private MetaManager metaManager;

    private static final long AUTH_CACHE_EXPIRE = 10 * 60L;
    private static final long AUTH_CACHE_CAPACITY = 1024 * 10L;
    private static final long AUTH_TOKEN_EXPIRE = 3600 * 24L;

    public StandardAuthManager(MetaManager metaManager, HugeConfig conf) {
        this.metaManager = metaManager;
        this.usersCache = this.cache("users", AUTH_CACHE_CAPACITY, AUTH_CACHE_EXPIRE);
        this.pwdCache = this.cache("users_pwd", AUTH_CACHE_CAPACITY, AUTH_CACHE_EXPIRE);
        this.tokenCache = this.cache("token", AUTH_CACHE_CAPACITY, AUTH_CACHE_EXPIRE);
        this.tokenGenerator = new TokenGenerator(conf);
    }

    private <V> Cache<Id, V> cache(String prefix, long capacity,
                                   long expiredTime) {
        String name = prefix + "-auth";
        Cache<Id, V> cache = CacheManager.instance().cache(name, capacity);
        if (expiredTime > 0L) {
            cache.expire(Duration.ofSeconds(expiredTime).toMillis());
        } else {
            cache.expire(expiredTime);
        }
        return cache;
    }

    @Override
    public boolean close() {
        return true;
    }

    private void invalidateUserCache() {
        this.usersCache.clear();
    }

    private void invalidatePasswordCache(Id id) {
        this.pwdCache.invalidate(id);
        // Clear all tokenCache because can't get userId in it
        this.tokenCache.clear();
    }

    @Override
    public Id createUser(HugeUser user) {
        Id username = IdGenerator.of(user.name());
        HugeUser existed = this.usersCache.get(username);
        E.checkArgument(existed == null,
                        "The user name '%s' has existed", user.name());

        try {
            this.metaManager.createUser(user);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "serialize user", e);
        }

        return username;
    }

    @Override
    public Id updateUser(HugeUser user) {
        Id username = IdGenerator.of(user.name());
        HugeUser existed = this.usersCache.get(username);
        if (existed != null) {
            this.invalidateUserCache();
            this.invalidatePasswordCache(user.id());
        }

        try {
            this.metaManager.updateUser(user);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "serialize user", e);
        }

        return username;
    }

    @Override
    public HugeUser deleteUser(Id id) {
        HugeUser existed = this.usersCache.get(id);
        if (existed != null) {
            this.invalidateUserCache();
            this.invalidatePasswordCache(id);
        }

        try {
            return this.metaManager.deleteUser(id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize user", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize user", e);
        }
    }

    @Override
    public HugeUser findUser(String name) {
        Id username = IdGenerator.of(name);
        HugeUser user = this.usersCache.get(username);
        if (user != null) {
            return user;
        }

        try {
            user = this.metaManager.findUser(name);
            if (user != null) {
                this.usersCache.update(username, user);
            }

            return user;
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize user", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize user", e);
        }
    }

    @Override
    public HugeUser getUser(Id id) {
        return this.findUser(id.asString());
    }

    @Override
    public List<HugeUser> listUsers(List<Id> ids) {
        try {
            return this.metaManager.listUsers(ids);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize user", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize user", e);
        }
    }

    @Override
    public List<HugeUser> listAllUsers(long limit) {
        try {
            return this.metaManager.listAllUsers(limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize user", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize user", e);
        }
    }

    @Override
    public Id createGroup(String graphSpace, HugeGroup group) {
        this.invalidateUserCache();
        try {
            return this.metaManager.createGroup(graphSpace, group);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "serialize group", e);
        }
    }

    @Override
    public Id updateGroup(String graphSpace, HugeGroup group) {
        this.invalidateUserCache();
        try {
            return this.metaManager.updateGroup(graphSpace, group);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "serialize group", e);
        }
    }

    @Override
    public HugeGroup deleteGroup(String graphSpace, Id id) {
        this.invalidateUserCache();
        try {
            return this.metaManager.deleteGroup(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize group", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize group", e);
        }
    }

    @Override
    public HugeGroup getGroup(String graphSpace, Id id) {
        try {
            return this.metaManager.getGroup(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize group", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize group", e);
        }
    }

    @Override
    public List<HugeGroup> listGroups(String graphSpace, List<Id> ids) {
        try {
            return this.metaManager.listGroups(graphSpace, ids);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize group", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize group", e);
        }
    }

    @Override
    public List<HugeGroup> listAllGroups(String graphSpace, long limit) {
        try {
            return this.metaManager.listAllGroups(graphSpace, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize group", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize group", e);
        }
    }

    @Override
    public Id createTarget(String graphSpace, HugeTarget target) {
        this.invalidateUserCache();
        try {
            return this.metaManager.createTarget(graphSpace, target);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "serialize target", e);
        }
    }

    @Override
    public Id updateTarget(String graphSpace, HugeTarget target) {
        this.invalidateUserCache();
        try {
            return this.metaManager.updateTarget(graphSpace, target);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "serialize target", e);
        }
    }

    @Override
    public HugeTarget deleteTarget(String graphSpace, Id id) {
        this.invalidateUserCache();
        try {
            return this.metaManager.deleteTarget(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize target", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize target", e);
        }
    }

    @Override
    public HugeTarget getTarget(String graphSpace, Id id) {
        try {
            return this.metaManager.getTarget(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize target", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize target", e);
        }
    }

    @Override
    public List<HugeTarget> listTargets(String graphSpace, List<Id> ids) {
        try {
            return this.metaManager.listTargets(graphSpace, ids);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize target", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize target", e);
        }
    }

    @Override
    public List<HugeTarget> listAllTargets(String graphSpace, long limit) {
        try {
            return this.metaManager.listAllTargets(graphSpace, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "deserialize target", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "deserialize target", e);
        }
    }

    @Override
    public Id createBelong(String graphSpace, HugeBelong belong) {
        this.invalidateUserCache();
        try {
            return this.metaManager.createBelong(graphSpace, belong);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "create belong", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "create belong", e);
        }
    }

    @Override
    public Id updateBelong(String graphSpace, HugeBelong belong) {
        this.invalidateUserCache();
        try {
            return this.metaManager.updateBelong(graphSpace, belong);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "update belong", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "update belong", e);
        }
    }

    @Override
    public HugeBelong deleteBelong(String graphSpace, Id id) {
        this.invalidateUserCache();
        try {
            return this.metaManager.deleteBelong(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "delete belong", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "delete belong", e);
        }
    }

    @Override
    public HugeBelong getBelong(String graphSpace, Id id) {
        try {
            return this.metaManager.getBelong(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get belong", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get belong", e);
        }
    }

    @Override
    public List<HugeBelong> listBelong(String graphSpace, List<Id> ids) {
        try {
            return this.metaManager.listBelong(graphSpace, ids);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get belong list by ids", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get belong list by ids", e);
        }
    }

    @Override
    public List<HugeBelong> listAllBelong(String graphSpace, long limit) {
        try {
            return this.metaManager.listAllBelong(graphSpace, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get all belong list", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get all belong list", e);
        }
    }

    @Override
    public List<HugeBelong> listBelongByUser(String graphSpace,
                                             Id user, long limit) {
        try {
            return this.metaManager.listBelongByUser(graphSpace, user, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get belong list by user", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get belong list by user", e);
        }
    }

    @Override
    public List<HugeBelong> listBelongByGroup(String graphSpace,
                                              Id group, long limit) {
        try {
            return this.metaManager.listBelongByGroup(graphSpace, group, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get belong list by group", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get belong list by group", e);
        }
    }

    @Override
    public Id createAccess(String graphSpace, HugeAccess access) {
        this.invalidateUserCache();
        try {
            return this.metaManager.createAccess(graphSpace, access);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "create access", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "create access", e);
        }
    }

    @Override
    public Id updateAccess(String graphSpace, HugeAccess access) {
        this.invalidateUserCache();
        try {
            return this.metaManager.updateAccess(graphSpace, access);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "update access", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "update access", e);
        }
    }

    @Override
    public HugeAccess deleteAccess(String graphSpace, Id id) {
        this.invalidateUserCache();
        try {
            return this.metaManager.deleteAccess(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "delete access", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "delete access", e);
        }
    }

    @Override
    public HugeAccess getAccess(String graphSpace, Id id) {
        try {
            return this.metaManager.getAccess(graphSpace, id);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get access", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get access", e);
        }
    }

    @Override
    public List<HugeAccess> listAccess(String graphSpace, List<Id> ids) {
        try {
            return this.metaManager.listAccess(graphSpace, ids);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get access list", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get access list", e);
        }
    }

    @Override
    public List<HugeAccess> listAllAccess(String graphSpace, long limit) {
        try {
            return this.metaManager.listAllAccess(graphSpace, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get all access list", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get all access list", e);
        }
    }

    @Override
    public List<HugeAccess> listAccessByGroup(String graphSpace,
                                              Id group, long limit) {
        try {
            return this.metaManager.listAccessByGroup(graphSpace, group, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get access list by group", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get access list by group", e);
        }
    }

    @Override
    public List<HugeAccess> listAccessByTarget(String graphSpace,
                                               Id target, long limit) {
        try {
            return this.metaManager.listAccessByTarget(graphSpace,
                                                       target, limit);
        } catch (IOException e) {
            throw new HugeException("IOException occurs when " +
                                    "get access list by target", e);
        } catch (ClassNotFoundException e) {
            throw new HugeException("ClassNotFoundException occurs when " +
                                    "get access list by target", e);
        }
    }

    @Override
    public HugeUser matchUser(String name, String password) {
        E.checkArgumentNotNull(name, "User name can't be null");
        E.checkArgumentNotNull(password, "User password can't be null");

        HugeUser user = this.findUser(name);
        if (user == null) {
            return null;
        }

        if (password.equals(this.pwdCache.get(user.id()))) {
            return user;
        }

        if (StringEncoding.checkPassword(password, user.password())) {
            this.pwdCache.update(user.id(), password);
            return user;
        }
        return null;
    }

    @Override
    public RolePermission rolePermission(String graphSpace, AuthElement element) {
        if (element instanceof HugeUser) {
            return this.rolePermission(graphSpace, (HugeUser) element);
        } else if (element instanceof HugeTarget) {
            return this.rolePermission((HugeTarget) element);
        }

        List<HugeAccess> accesses = new ArrayList<>();
        if (element instanceof HugeBelong) {
            HugeBelong belong = (HugeBelong) element;
            accesses.addAll(this.listAccessByGroup(graphSpace,
                                                   belong.target(), -1));
        } else if (element instanceof HugeGroup) {
            HugeGroup group = (HugeGroup) element;
            accesses.addAll(this.listAccessByGroup(graphSpace, group.id(), -1));
        } else if (element instanceof HugeAccess) {
            HugeAccess access = (HugeAccess) element;
            accesses.add(access);
        } else {
            E.checkArgument(false, "Invalid type for role permission: %s",
                            element);
        }

        return this.rolePermission(graphSpace, element);
    }

    private RolePermission rolePermission(String graphSpace, HugeUser user) {
        if (user.role() != null) {
            // Return cached role (40ms => 10ms)
            return user.role();
        }

        // Collect accesses by user
        List<HugeAccess> accesses = new ArrayList<>();
        List<HugeBelong> belongs = this.listBelongByUser(graphSpace,
                                                         user.id(), -1);
        for (HugeBelong belong : belongs) {
            accesses.addAll(this.listAccessByGroup(graphSpace,
                                                   belong.target(), -1));
        }

        // Collect permissions by accesses
        RolePermission role = this.rolePermission(graphSpace, accesses);

        user.role(role);
        return role;
    }

    private RolePermission rolePermission(String graphSpace, List<HugeAccess> accesses) {
        // Mapping of: graph -> action -> resource
        RolePermission role = new RolePermission();
        for (HugeAccess access : accesses) {
            HugePermission accessPerm = access.permission();
            HugeTarget target = this.getTarget(graphSpace, access.target());
            role.add(target.graph(), accessPerm, target.resources());
        }
        return role;
    }

    private RolePermission rolePermission(HugeTarget target) {
        RolePermission role = new RolePermission();
        // TODO: improve for the actual meaning
        role.add(target.graph(), HugePermission.READ, target.resources());
        return role;
    }

    @Override
    public String loginUser(String username, String password,
                            long expire)
                            throws AuthenticationException {
        HugeUser user = this.matchUser(username, password);
        if (user == null) {
            String msg = "Incorrect username or password";
            throw new AuthenticationException(msg);
        }

        Map<String, ?> payload = ImmutableMap.of(AuthConstant.TOKEN_USER_NAME,
                                                 username,
                                                 AuthConstant.TOKEN_USER_ID,
                                                 user.id.asString());
        expire = expire == 0L ? AUTH_TOKEN_EXPIRE : expire;
        String token = this.tokenGenerator.create(payload, expire * 1000);
        this.tokenCache.update(IdGenerator.of(token), username);
        return token;
    }

    @Override
    public void logoutUser(String token) {
        this.tokenCache.invalidate(IdGenerator.of(token));
    }

    @Override
    public String createToken(String username) {
        HugeUser user = this.findUser(username);
        if (user == null) {
            return null;
        }

        Map<String, ?> payload = ImmutableMap.of(AuthConstant.TOKEN_USER_NAME,
                                                 username,
                                                 AuthConstant.TOKEN_USER_ID,
                                                 user.id.asString());
        String token = this.tokenGenerator.create(payload, AUTH_TOKEN_EXPIRE);
        this.tokenCache.update(IdGenerator.of(token), username);
        return token;
    }

    @Override
    public UserWithRole validateUser(String username, String password) {
        HugeUser user = this.matchUser(username, password);
        if (user == null) {
            return new UserWithRole(username);
        }
        return new UserWithRole(user.id, username, this.rolePermission(user));
    }

    @Override
    public UserWithRole validateUser(String token) {
        String username = this.tokenCache.get(IdGenerator.of(token));

        Claims payload = this.tokenGenerator.verify(token);
        boolean needBuildCache = false;
        if (username == null) {
            username = (String) payload.get(AuthConstant.TOKEN_USER_NAME);
            needBuildCache = true;
        }

        HugeUser user = this.findUser(username);
        if (user == null) {
            return new UserWithRole(username);
        } else if (needBuildCache) {
            long expireAt = payload.getExpiration().getTime();
            long bornTime = this.tokenCache.expire() -
                            (expireAt - System.currentTimeMillis());
            this.tokenCache.update(IdGenerator.of(token), username,
                                   Math.negateExact(bornTime));
        }

        return new UserWithRole(user.id(), username, this.rolePermission(user));
    }

    /**
     * Maybe can define an proxy class to choose forward or call local
     */
    public static boolean isLocal(AuthManager authManager) {
        return authManager instanceof StandardAuthManager;
    }
}
