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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.baidu.hugegraph.backend.id.IdGenerator;
import org.apache.commons.lang3.StringUtils;
import org.apache.tinkerpop.gremlin.structure.Graph.Hidden;
import org.apache.tinkerpop.gremlin.structure.T;

import com.baidu.hugegraph.HugeException;
import com.baidu.hugegraph.HugeGraphParams;
import com.baidu.hugegraph.auth.SchemaDefine.Entity;
import com.baidu.hugegraph.backend.id.Id;
import com.baidu.hugegraph.schema.VertexLabel;
import com.baidu.hugegraph.util.E;
import com.baidu.hugegraph.util.JsonUtil;

import jersey.repackaged.com.google.common.collect.ImmutableList;
import org.apache.tinkerpop.shaded.jackson.core.type.TypeReference;

public class HugeTarget extends Entity {

    private static final long serialVersionUID = -3361487778656878418L;

    private String name;
    private String graphSpace;
    private String graph;
    private Map<String, List<HugeResource>> resources;

    public static final String POUND_SEPARATOR = "#";

    private static final Map<String, List<HugeResource>> EMPTY = new HashMap<>();

    public HugeTarget(Id id) {
        this(id, null, null, null, EMPTY);
    }

    public HugeTarget(String name, String graphSpace) {
        this(StringUtils.isNotEmpty(name) ? IdGenerator.of(name) : null, name,
             graphSpace,  name, EMPTY);
    }

    public HugeTarget(String name, String graphSpace, String graph) {
        this(StringUtils.isNotEmpty(name) ? IdGenerator.of(name) : null, name,
             graphSpace, graph, EMPTY);
    }

    public HugeTarget(String name, String graphSpace, String graph,
                      Map<String, List<HugeResource>> resources) {
        this(StringUtils.isNotEmpty(name) ? IdGenerator.of(name) : null, name,
             graphSpace, graph, resources);
    }

    private HugeTarget(Id id, String name, String graphSpace, String graph,
                       Map<String, List<HugeResource>> resources) {
        this.id = id;
        this.name = name;
        this.graphSpace = graphSpace;
        this.graph = graph;
        this.resources = resources;
    }

    @Override
    public ResourceType type() {
        return ResourceType.TARGET;
    }

    @Override
    public String label() {
        return P.TARGET;
    }

    @Override
    public String name() {
        return this.name;
    }

    public String graphSpace() {
        return this.graphSpace;
    }

    public String graph() {
        return this.graph;
    }

    public Map<String, List<HugeResource>> resources() {
        return this.resources;
    }

    public void resources(String resources) {
        try {
            this.resources = HugeResource.parseResources(resources);
        } catch (Exception e) {
            throw new HugeException("Invalid format of resources: %s",
                                    e, resources);
        }
    }

    public void resources(List<Map<String, Object>> resources) {
        E.checkNotNull(resources, "resources");
        Map<String, List<HugeResource>> ressMap = new HashMap<>();
        for (Map<String, Object> entry: resources) {
            ResourceType type =
                    ResourceType.valueOf(entry.get("type").toString());
            String label = (entry.get("label") == null)?
                    null : entry.get("label").toString();

            String typeLabel;
            // decide typeLabel
            if (type.isGraphOrSchema()) {
                typeLabel = type + POUND_SEPARATOR + label;
            } else {
                typeLabel = type.toString();
            }

            HugeResource hr = new HugeResource(
                    type, label, (Map<String, Object>)entry.get("properties"));
            List<HugeResource> ress = ressMap.get(typeLabel);
            if (ress == null) {
                ress = Arrays.asList(hr);
                ressMap.put(typeLabel, ress);
            } else {
                ress.add(hr);
            }
        }
        this.resources = ressMap;
    }

    public void resources(Map<String, List<HugeResource>> resources) {
        E.checkNotNull(resources, "resources");
        this.resources = resources;
    }

    @Override
    public String toString() {
        return String.format("HugeTarget(%s)", this.id);
    }

    @Override
    protected boolean property(String key, Object value) {
        if (super.property(key, value)) {
            return true;
        }
        switch (key) {
            case P.NAME:
                this.name = (String) value;
                break;
            case P.GRAPHSPACE:
                this.graphSpace = (String) value;
                break;
            case P.GRAPH:
                this.graph = (String) value;
                break;
            case P.RESS:
                // this.resources = (Map<String, List<HugeResource>>)) value;
                this.resources =
                        JsonUtil.fromJson(
                                JsonUtil.toJson(value),
                                new TypeReference<Map<String,
                                        List<HugeResource>>>(){});
                break;
            default:
                throw new AssertionError("Unsupported key: " + key);
        }
        return true;
    }

    @Override
    protected Object[] asArray() {
        E.checkState(this.name != null, "Target name can't be null");

        List<Object> list = new ArrayList<>(16);

        list.add(T.label);
        list.add(P.TARGET);

        list.add(P.NAME);
        list.add(this.name);

        list.add(P.GRAPHSPACE);
        list.add(this.graphSpace);

        list.add(P.GRAPH);
        list.add(this.graph);

        if (this.resources != null && this.resources != EMPTY) {
            list.add(P.RESS);
            list.add(this.resources);
        }

        return super.asArray(list);
    }

    @Override
    public Map<String, Object> asMap() {
        E.checkState(this.name != null, "Target name can't be null");

        Map<String, Object> map = new HashMap<>();

        map.put(Hidden.unHide(P.NAME), this.name);
        map.put(Hidden.unHide(P.GRAPHSPACE), this.graphSpace);
        map.put(Hidden.unHide(P.GRAPH), this.graph);

        if (this.resources != null && this.resources != EMPTY) {
            map.put(Hidden.unHide(P.RESS), this.resources);
        }

        return super.asMap(map);
    }

    public static HugeTarget fromMap(Map<String, Object> map) {
        HugeTarget target = new HugeTarget(null);
        return fromMap(map, target);
    }

    public static Schema schema(HugeGraphParams graph) {
        return new Schema(graph);
    }

    public static final class P {

        public static final String TARGET = Hidden.hide("target");

        public static final String ID = T.id.getAccessor();
        public static final String LABEL = T.label.getAccessor();

        public static final String NAME = "~target_name";
        public static final String GRAPHSPACE = "~graphspace";
        public static final String GRAPH = "~target_graph";
        public static final String RESS = "~target_resources";

        public static String unhide(String key) {
            final String prefix = Hidden.hide("target_");
            if (key.startsWith(prefix)) {
                return key.substring(prefix.length());
            }
            return key;
        }
    }

    public static final class Schema extends SchemaDefine {

        public Schema(HugeGraphParams graph) {
            super(graph, P.TARGET);
        }

        @Override
        public void initSchemaIfNeeded() {
            if (this.existVertexLabel(this.label)) {
                return;
            }

            String[] properties = this.initProperties();

            // Create vertex label
            VertexLabel label = this.schema().vertexLabel(this.label)
                                    .properties(properties)
                                    .usePrimaryKeyId()
                                    .primaryKeys(P.NAME)
                                    .nullableKeys(P.RESS)
                                    .enableLabelIndex(true)
                                    .build();
            this.graph.schemaTransaction().addVertexLabel(label);
        }

        private String[] initProperties() {
            List<String> props = new ArrayList<>();

            props.add(createPropertyKey(P.NAME));
            props.add(createPropertyKey(P.GRAPH));
            props.add(createPropertyKey(P.RESS));

            return super.initProperties(props);
        }
    }
}
