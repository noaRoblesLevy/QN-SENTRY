import { LoaderCircle } from 'lucide-react'
import './Spinner.css'

// The only looping animation allowed by the house style: a scan in progress
function Spinner({ size = 16 }: { size?: number }) {
  return <LoaderCircle className="spinner" size={size} strokeWidth={1.5} aria-hidden="true" />
}

export default Spinner
