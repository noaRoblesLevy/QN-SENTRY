export type Domain = {
  id: number
  name: string
}

export type Client = {
  id: number
  name: string
  domains: Domain[]
}