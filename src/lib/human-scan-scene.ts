import * as THREE from "three";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";
import { MeshSurfaceSampler } from "three/examples/jsm/math/MeshSurfaceSampler.js";
import { mergeVertices } from "three/examples/jsm/utils/BufferGeometryUtils.js";

/** A single disposable WebGL scene; no React state changes in the render loop. */
export async function init(canvas: HTMLCanvasElement, signal?: AbortSignal) {
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: false, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.setClearColor(0x000000, 0);
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(33, 1, 0.1, 40);
  camera.position.set(0, 0, 9.8);
  const group = new THREE.Group();
  const yaw = -0.78;
  group.position.x = -0.4;
  scene.add(group);
  const geometries: THREE.BufferGeometry[] = [];
  const materials: THREE.Material[] = [];
  let frame = 0;
  let disposed = false;
  let visible = true;
  let paused = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let targetX = 0;
  let targetY = 0;
  const resize = () => {
    const { width, height } = canvas.getBoundingClientRect();
    renderer.setSize(Math.max(width, 1), Math.max(height, 1), false);
    camera.aspect = width / Math.max(height, 1);
    camera.updateProjectionMatrix();
  };
  const observer = new ResizeObserver(resize);
  observer.observe(canvas);
  const intersection = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; });
  intersection.observe(canvas);
  const pointer = (event: PointerEvent) => {
    const rect = canvas.getBoundingClientRect();
    targetY = ((event.clientX - rect.left) / rect.width - 0.5) * 0.22;
    targetX = ((event.clientY - rect.top) / rect.height - 0.5) * 0.1;
  };
  canvas.addEventListener("pointermove", pointer);
  const resetPointer = () => { targetX = 0; targetY = 0; };
  canvas.addEventListener("pointerleave", resetPointer);
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  const onMotion = () => { paused = motion.matches; };
  motion.addEventListener("change", onMotion);
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    cancelAnimationFrame(frame);
    observer.disconnect();
    intersection.disconnect();
    canvas.removeEventListener("pointermove", pointer);
    canvas.removeEventListener("pointerleave", resetPointer);
    motion.removeEventListener("change", onMotion);
    signal?.removeEventListener("abort", dispose);
    geometries.forEach((geometry) => geometry.dispose());
    materials.forEach((material) => material.dispose());
    renderer.dispose();
  };
  signal?.addEventListener("abort", dispose, { once: true });
  try {
    const response = await fetch("/models/head.glb", { signal });
    if (!response.ok) throw new Error("The human scan model could not be loaded.");
    const gltf = await new GLTFLoader().parseAsync(await response.arrayBuffer(), "/models/");
    if (disposed) {
      gltf.scene.traverse((object) => {
        if (object instanceof THREE.Mesh) {
          object.geometry.dispose();
          (Array.isArray(object.material) ? object.material : [object.material]).forEach((material) => material.dispose());
        }
      });
      throw new DOMException("Aborted", "AbortError");
    }
    let mesh: THREE.Mesh | undefined;
    gltf.scene.updateMatrixWorld(true);
    gltf.scene.traverse((object) => {
      if (object instanceof THREE.Mesh) {
        if (!mesh) mesh = object;
        geometries.push(object.geometry);
        materials.push(...(Array.isArray(object.material) ? object.material : [object.material]));
      }
    });
    if (!mesh) throw new Error("The human scan model contains no surface.");
    const geometry = mesh.geometry.clone().applyMatrix4(mesh.matrixWorld);
    geometry.computeBoundingBox();
    const bounds = geometry.boundingBox!;
    const center = bounds.getCenter(new THREE.Vector3());
    const scale = 4.8 / (bounds.max.y - bounds.min.y);
    geometry.translate(-center.x, -center.y, -center.z);
    geometry.scale(scale, scale, scale);
    geometry.translate(-0.25, 0.05, 0);
    geometry.computeVertexNormals();
    geometries.push(geometry);
    const depthMaterial = new THREE.MeshBasicMaterial({ color: 0x000000, polygonOffset: true, polygonOffsetFactor: 1, polygonOffsetUnits: 1 });
    materials.push(depthMaterial);
    group.add(new THREE.Mesh(geometry, depthMaterial));
    // Weld the scan into a readable lattice instead of drawing every tiny triangle.
    const latticeSource = geometry.clone();
    for (const name of Object.keys(latticeSource.attributes)) if (name !== "position") latticeSource.deleteAttribute(name);
    const lattice = mergeVertices(latticeSource, 0.055);
    const wireGeometry = new THREE.WireframeGeometry(lattice);
    latticeSource.dispose();
    lattice.dispose();
    const wireMaterial = new THREE.ShaderMaterial({
      transparent: true, depthWrite: false,
      uniforms: { yaw: { value: yaw } },
      vertexShader: `uniform float yaw; varying float strength; void main(){
        float screenX=cos(yaw)*position.x+sin(yaw)*position.z;
        strength = mix(.17,.34,smoothstep(-1.8,.3,position.y));
        strength *= 1.-smoothstep(-.15,.8,screenX)*.93;
        strength *= smoothstep(-2.35,-1.8,position.y);
        gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);
      }`,
      fragmentShader: "varying float strength; void main(){gl_FragColor=vec4(vec3(.92,.94,.93),strength);}",
    });
    geometries.push(wireGeometry);
    materials.push(wireMaterial);
    group.add(new THREE.LineSegments(wireGeometry, wireMaterial));
    let seed = 419;
    const random = () => { seed = (Math.imul(seed, 1664525) + 1013904223) | 0; return (seed >>> 0) / 4294967296; };
    const sampler = new MeshSurfaceSampler(new THREE.Mesh(geometry)).build();
    const positions: number[] = [];
    const strengths: number[] = [];
    const sizes: number[] = [];
    const fragments: number[] = [];
    const fragmentColors: number[] = [];
    const sideways = new THREE.Vector3(Math.cos(yaw), 0, Math.sin(yaw));
    const segment = (a: THREE.Vector3, b: THREE.Vector3, brightness: number) => {
      fragments.push(a.x,a.y,a.z,b.x,b.y,b.z);
      for(let j=0;j<2;j++) fragmentColors.push(brightness,brightness,brightness);
    };
    const point = new THREE.Vector3();
    const normal = new THREE.Vector3();
    for (let i = 0; i < 18000; i++) {
      sampler.sample(point, normal);
      point.addScaledVector(normal, 0.007);
      const dissolve = THREE.MathUtils.smoothstep(point.x, -0.1, 1.15);
      const facing = Math.max(0, -Math.sin(yaw)*normal.x + Math.cos(yaw)*normal.z);
      const face = THREE.MathUtils.smoothstep(point.y, -1.1, 0.2);
      const displaced = random() < dissolve * 0.63;
      if (displaced) {
        point.addScaledVector(sideways, 0.12 + Math.pow(random(), 1.6) * 1.65);
        point.y = Math.round(point.y / 0.045) * 0.045;
        if (i % 9 === 0 && point.y > -1.85) {
          segment(point, point.clone().addScaledVector(sideways, 0.035 + random() * 0.24), 0.16 + random()*0.38);
        }
        if (i % 33 === 0 && point.y > -1.85) {
          const width = 0.025 + Math.pow(random(),3)*0.13;
          const a=point.clone(), b=a.clone().addScaledVector(sideways,width);
          const c=b.clone().add(new THREE.Vector3(0,width,0)), d=a.clone().add(new THREE.Vector3(0,width,0));
          for(const [from,to] of [[a,b],[b,c],[c,d],[d,a]]) segment(from,to,0.35+random()*.3);
        }
      }
      positions.push(point.x, point.y, point.z);
      strengths.push(displaced ? 0.18+random()*.5 : (0.38 + facing*.5 + random()*.3) * (0.6+face*.4));
      sizes.push(displaced ? 0.7+random()*.6 : 0.9+face*.4+random()*.55);
    }
    const pointGeometry = new THREE.BufferGeometry();
    pointGeometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    pointGeometry.setAttribute("strength", new THREE.Float32BufferAttribute(strengths, 1));
    pointGeometry.setAttribute("size", new THREE.Float32BufferAttribute(sizes, 1));
    const pointMaterial = new THREE.ShaderMaterial({
      transparent: true, depthWrite: false,
      uniforms: { pixelRatio: {value: renderer.getPixelRatio()}, time: {value:0} },
      vertexShader: `attribute float strength; attribute float size; uniform float pixelRatio; uniform float time; varying float alpha;
        void main(){float band=exp(-pow((position.y-sin(time*.35)*2.6)*5.,2.)); alpha=strength+band*.18;
        vec4 p=modelViewMatrix*vec4(position,1.); gl_PointSize=clamp(size*pixelRatio*9./-p.z,1.,4.); gl_Position=projectionMatrix*p;}`,
      fragmentShader: "varying float alpha; void main(){float d=length(gl_PointCoord-.5); if(d>.5) discard; gl_FragColor=vec4(vec3(.97,.98,1.),alpha*(1.-smoothstep(.22,.5,d)));}",
    });
    geometries.push(pointGeometry);
    materials.push(pointMaterial);
    group.add(new THREE.Points(pointGeometry, pointMaterial));
    const fragmentGeometry = new THREE.BufferGeometry();
    fragmentGeometry.setAttribute("position",new THREE.Float32BufferAttribute(fragments,3));
    fragmentGeometry.setAttribute("color",new THREE.Float32BufferAttribute(fragmentColors,3));
    const fragmentMaterial = new THREE.LineBasicMaterial({vertexColors:true,transparent:true,opacity:0.85,depthWrite:false});
    geometries.push(fragmentGeometry);
    materials.push(fragmentMaterial);
    group.add(new THREE.LineSegments(fragmentGeometry,fragmentMaterial));
    group.rotation.y = yaw;
    resize();
    let time = 0;
    let previousTime = performance.now();
    const render = () => {
      if (disposed) return;
      frame = requestAnimationFrame(render);
      const now = performance.now();
      const delta = Math.min((now-previousTime)/1000,0.05);
      previousTime = now;
      if (!visible || document.hidden) return;
      if (!paused) {
        time += delta;
        const ease = 1-Math.exp(-delta*2);
        group.rotation.y += (yaw + Math.sin(time * 0.16) * 0.055 + targetY - group.rotation.y) * ease;
        group.rotation.x += (targetX - group.rotation.x) * ease;
        pointMaterial.uniforms.time.value = time;
      }
      renderer.render(scene, camera);
    };
    render();
    return { dispose, setPaused: (value: boolean) => { paused = value; } };
  } catch (error) {
    dispose();
    throw error;
  }
}
