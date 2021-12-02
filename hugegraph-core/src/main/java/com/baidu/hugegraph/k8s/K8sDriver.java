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

package com.baidu.hugegraph.k8s;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.baidu.hugegraph.HugeException;
import com.baidu.hugegraph.space.GraphSpace;
import com.baidu.hugegraph.space.Service;

import io.fabric8.kubernetes.api.model.ListOptions;
import io.fabric8.kubernetes.api.model.Namespace;
import io.fabric8.kubernetes.api.model.NamespaceBuilder;
import io.fabric8.kubernetes.api.model.NamespaceList;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodBuilder;
import io.fabric8.kubernetes.api.model.Quantity;
import io.fabric8.kubernetes.api.model.ResourceRequirements;
import io.fabric8.kubernetes.api.model.ResourceRequirementsBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.DeploymentBuilder;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.DefaultKubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClient;

public class K8sDriver {

    public static final String DELIMETER = "-";

    private static final String CONTAINER = "container";
    private static final String APP = "app";

    private KubernetesClient client;

    private String oltpImage;
    private String olapImage;
    private String storageImage;

    public K8sDriver(String url) {
        Config config = new ConfigBuilder().withMasterUrl(url).build();
        this.client = new DefaultKubernetesClient(config);
    }

    public String oltpImage() {
        return this.oltpImage;
    }

    public void oltpImage(String oltpImage) {
        this.oltpImage = oltpImage;
    }

    public String olapImage() {
        return this.olapImage;
    }

    public void olapImage(String olapImage) {
        this.olapImage = olapImage;
    }

    public String storageImage() {
        return this.storageImage;
    }

    public void storageImage(String storageImage) {
        this.storageImage = storageImage;
    }

    public Namespace namespace(String ns) {
        NamespaceList nameSpaceList = this.client.namespaces().list();
        List<Namespace> namespaceList = nameSpaceList.getItems();
        for (Namespace namespace : namespaceList) {
            if (namespace.getMetadata().getName().equals(ns)) {
                return namespace;
            }
        }
        return null;
    }

    public List<Namespace> namespaces() {
        NamespaceList nameSpaceList = this.client.namespaces().list();
        return nameSpaceList.getItems();
    }

    public List<String> namespaceNames() {
        List<String> names = new ArrayList<>();
        NamespaceList nameSpaceList = this.client.namespaces().list();
        for (Namespace namespace : nameSpaceList.getItems()) {
            names.add(namespace.getMetadata().getName());
        }
        return names;
    }

    public Namespace createNamespace(String name, Map<String, String> labels) {
        Namespace namespace = new NamespaceBuilder()
                .withNewMetadata()
                .withName(name)
                .addToLabels(labels)
                .endMetadata()
                .build();
        return this.client.namespaces().createOrReplace(namespace);
    }

    public boolean deleteNamespace(String name) {
        return this.client.namespaces().withName(name).delete();
    }

    public Pod createPod(String namespace, String podName,
                         Map<String, String> labels,
                         String containerName, String image) {
        Pod pod = new PodBuilder()
                .withNewMetadata()
                .withName(podName)
                .addToLabels(labels)
                .endMetadata()
                .withNewSpec()
                .addNewContainer()
                .withName(containerName)
                .withImage(image)
                .endContainer()
                .endSpec()
                .build();
        return this.client.pods().inNamespace(namespace).createOrReplace(pod);
    }

    public List<Pod> pods(String namespace) {
        return this.client.pods().inNamespace(namespace).list().getItems();
    }

    public Pod pod(String namespace, String podName) {
        return this.client.pods()
                          .inNamespace(namespace)
                          .withName(podName)
                          .get();
    }

    public Set<String> startOltpService(GraphSpace graphSpace,
                                        Service service) {
        Deployment deployment = this.constructDeployment(graphSpace, service);
        String namespace = namespace(graphSpace, service);
        this.client.apps().deployments().inNamespace(namespace)
                   .createOrReplace(deployment);

        ListOptions options = new ListOptions();
        options.setLabelSelector(APP + "=" + serviceName(graphSpace, service));
        List<Pod> hugegraphservers = new ArrayList<>();
        int count = 0;
        while (hugegraphservers.isEmpty() && count++ < 10) {
            hugegraphservers = this.client.pods()
                                          .inNamespace(namespace)
                                          .list(options)
                                          .getItems();
            sleepAWhile(1);
        }
        if (hugegraphservers.isEmpty()) {
            throw new HugeException("Failed to start oltp server");
        }
        Set<String> urls = new HashSet<>();

        for (Pod hugegraphserver : hugegraphservers) {
            String podIP = hugegraphserver.getStatus().getPodIP();
            int times = 0;
            String podName = hugegraphserver.getMetadata().getName();
            while (podIP == null && times++ < 10) {
                sleepAWhile(1);
                hugegraphserver = this.pod(namespace, podName);
                podIP = hugegraphserver.getStatus().getPodIP();
            }
            if (podIP == null) {
                throw new HugeException("Failed to get pod ip for %s", podName);
            }
            urls.add(podIP + ":8080");
        }
        return urls;
    }

    public void stopOltpService(GraphSpace graphSpace, Service service) {
        String deploymentName = serviceName(graphSpace, service);
        String namespace = namespace(graphSpace, service);
        this.client.apps().deployments().inNamespace(namespace)
                   .withName(deploymentName).delete();
    }

    private Deployment constructDeployment(GraphSpace graphSpace,
                                           Service service) {
        String deploymentName = serviceName(graphSpace, service);
        String containerName = String.join(DELIMETER, deploymentName,
                                           CONTAINER);
        Quantity cpu = Quantity.parse((service.cpuLimit() * 100) + "m");
        Quantity memory = Quantity.parse(service.memoryLimit() + "G");
        ResourceRequirements rr = new ResourceRequirementsBuilder()
                .addToLimits("cpu", cpu)
                .addToLimits("memory", memory)
                .build();

        Deployment deployment = new DeploymentBuilder()
                .withNewMetadata()
                .withName(deploymentName)
                .addToLabels(APP, deploymentName)
                .endMetadata()
                .withNewSpec()
                .withReplicas(service.count())
                .withNewTemplate()
                .withNewMetadata()
                .addToLabels(APP, deploymentName)
                .endMetadata()
                .withNewSpec()
                .addNewContainer()
                .withName(containerName)
                .withImage(this.image(service))
                .withResources(rr)
                .addNewPort()
                .withContainerPort(80)
                .endPort()
                .endContainer()
                .endSpec()
                .endTemplate()
                .withNewSelector()
                .addToMatchLabels(APP, deploymentName)
                .endSelector()
                .endSpec()
                .build();
        return deployment;
    }

    private static String namespace(GraphSpace graphSpace, Service service) {
        String namespace;
        switch (service.type()) {
            case OLTP:
                namespace = graphSpace.oltpNamespace;
                break;
            case OLAP:
            case STORAGE:
            default:
                throw new AssertionError(String.format(
                          "Invalid service type '%s'", service.type()));
        }
        return namespace;
    }

    private String image(Service service) {
        switch (service.type()) {
            case OLTP:
                return this.oltpImage;
            case OLAP:
                return this.olapImage;
            case STORAGE:
                return this.storageImage;
            default:
                throw new AssertionError(String.format(
                          "Invalid service type '%s'", service.type()));
        }
    }

    private static String serviceName(String graphSpace,
                                      Service service) {
        return String.join(DELIMETER, graphSpace,
                           service.type().name().toLowerCase(), service.name());
    }

    private static String serviceName(GraphSpace graphSpace,
                                      Service service) {
        return String.join(DELIMETER, graphSpace.name(),
                           service.type().name().toLowerCase(), service.name());
    }

    private static void sleepAWhile(int second) {
        try {
            Thread.sleep(second * 1000L);
        } catch (InterruptedException e) {
            // Ignore
        }
    }
}
