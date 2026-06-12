/**
 * /assets — placeholder; device management moved to /devices.
 */
import { Navigate } from "react-router-dom";

export default function Assets() {
  return <Navigate to="/devices" replace />;
}
