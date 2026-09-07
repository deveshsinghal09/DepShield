import * as THREE from "three";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";
import { MeshSurfaceSampler } from "three/examples/jsm/math/MeshSurfaceSampler.js";

/** A single disposable WebGL scene; no React state changes in the render loop. */
export async function init(canvas: HTMLCanvasElement, signal?: AbortSignal) {
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: false, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));
  renderer.setClearColor(0x000000, 0);
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(33, 1, 0.1, 40);
  camera.position.set(0, 0, 9.8);
  const group = new THREE.Group();
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
    const scale = 3.9 / (bounds.max.y - bounds.min.y);
    geometry.translate(-center.x, -center.y, -center.z);
    geometry.scale(scale, scale, scale);
    geometry.translate(0, 0.3, 0);
    geometry.computeVertexNormals();
    geometries.push(geometry);
    const depthMaterial = new THREE.MeshBasicMaterial({ color: 0x020303, polygonOffset: true, polygonOffsetFactor: 1, polygonOffsetUnits: 1 });
    materials.push(depthMaterial);
    group.add(new THREE.Mesh(geometry, depthMaterial));
    const wireGeometry = new THREE.WireframeGeometry(geometry);
    const wireMaterial = new THREE.LineBasicMaterial({ color: 0x87928e, transparent: true, opacity: 0.15, depthWrite: false });
    geometries.push(wireGeometry);
    materials.push(wireMaterial);
    group.add(new THREE.LineSegments(wireGeometry, wireMaterial));
    let seed = 419;
    const random = () => { seed = (Math.imul(seed, 1664525) + 1013904223) | 0; return (seed >>> 0) / 4294967296; };
    const sampler = new MeshSurfaceSampler(new THREE.Mesh(geometry)).build();
    const positions: number[] = [];
    const strengths: number[] = [];
    const point = new THREE.Vector3();
    const normal = new THREE.Vector3();
    for (let i = 0; i < 18000; i++) {
      sampler.sample(point, normal);
      point.addScaledVector(normal, 0.007);
      const dissolve = Math.max(0, point.x - 0.35) * random();
      if (dissolve > 0.2 && random() > 0.4) {
        point.x += dissolve * 2.6;
        point.y += (random() - 0.5) * dissolve;
      }
      positions.push(point.x, point.y, point.z);
      strengths.push(0.25 + random() * 0.7);
    }
    const pointGeometry = new THREE.BufferGeometry();
    pointGeometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    pointGeometry.setAttribute("strength", new THREE.Float32BufferAttribute(strengths, 1));
    const pointMaterial = new THREE.ShaderMaterial({
      transparent: true, depthWrite: false,
      vertexShader: "attribute float strength; varying float alpha; void main(){alpha=strength; vec4 p=modelViewMatrix*vec4(position,1.); gl_PointSize=clamp(12./-p.z,1.,2.5); gl_Position=projectionMatrix*p;}",
      fragmentShader: "varying float alpha; void main(){float d=length(gl_PointCoord-.5); if(d>.5) discard; gl_FragColor=vec4(vec3(.87,.91,.89),alpha*(1.-smoothstep(.3,.5,d)));}",
    });
    geometries.push(pointGeometry);
    materials.push(pointMaterial);
    group.add(new THREE.Points(pointGeometry, pointMaterial));
    group.rotation.y = -0.6;
    resize();
    let time = 0;
    const render = () => {
      if (disposed) return;
      frame = requestAnimationFrame(render);
      if (!visible || document.hidden) return;
      if (!paused) {
        time += 0.008;
        group.rotation.y += (-0.6 + Math.sin(time * 0.16) * 0.1 + targetY - group.rotation.y) * 0.025;
        group.rotation.x += (targetX - group.rotation.x) * 0.025;
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
