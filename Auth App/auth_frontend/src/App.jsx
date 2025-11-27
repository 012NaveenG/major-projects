import { Route, BrowserRouter, Routes } from "react-router-dom"
import IndexLayout from "./layouts/IndexLayout"
const App = () => {
  return (
    <BrowserRouter>
      <Routes>

        <Route element={<IndexLayout />}>
          <Route path="/" element={"Home Page"} />
          <Route path="/login" element={"Login Page"} />
        </Route>

      </Routes>
    </BrowserRouter>
  )
}

export default App
