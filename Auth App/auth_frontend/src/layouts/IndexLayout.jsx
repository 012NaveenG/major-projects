import { Outlet } from "react-router-dom"

const IndexLayout = () => {
    return (
        <div>
            <h1>Index Layout</h1>
            <Outlet />
        </div>
    )
}

export default IndexLayout
