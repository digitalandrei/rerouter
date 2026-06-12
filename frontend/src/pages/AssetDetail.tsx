/**
 * /assets/:id — placeholder; redirects to the device detail page.
 */
import { useParams, Navigate } from "react-router-dom";

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>();
  return <Navigate to={`/devices/${id ?? ""}`} replace />;
}
